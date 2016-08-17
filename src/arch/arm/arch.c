#include <common.h>

#include <sys/syscall.h>
#include <linux/ptrace.h>
#include <sys/mman.h>

INJECTION_DECLARE(inj_trap_arm);
INJECTION_DECLARE(inj_trap_thumb);

#ifndef is_wide_instruction
#define is_wide_instruction(instr)      ((unsigned)(instr) >= 0xe800)
#endif

#ifndef thumb_mode
#define thumb_mode(regs) (((regs)->ARM_cpsr & PSR_T_BIT))
#endif

void syshook_arch_get_state(syshook_process_t* process, void* state) {
    syshook_internal_t* pdata = state;
    struct pt_regs* regs = (void*)pdata->regs;

    safe_ptrace(PTRACE_GETREGS, process->tid, 0, regs);
    pdata->result = syshook_arch_argument_get(state, 0);

    // reset
    pdata->lowargs_changed = false;
    pdata->highargs_changed = false;
    pdata->scno_changed = false;
    pdata->result_changed = false;
}

void syshook_arch_set_state(syshook_process_t* process, void* state) {
    syshook_internal_t* pdata = state;
    struct pt_regs* regs = (void*)pdata->regs;

    if(pdata->scno_changed) {
        //LOGD("apply scno\n");
        safe_ptrace(PTRACE_SET_SYSCALL, process->tid, 0, (void*)regs->ARM_r7);
    }

    if(pdata->highargs_changed && syshook_arch_is_entry(state)) {
        //LOGD("apply highregs\n");

        int status;
        parsed_status_t parsed_status;

        // backup regs
        int scno = syshook_arch_syscall_get(state);
        long a0 = syshook_arch_argument_get(state, 0);

        // get pc and instruction
        unsigned long instr;
        long pc = syshook_arch_get_pc(state);
        if(syshook_copy_from_user(process, &instr, (void*)pc, sizeof(instr))) {
            LOGF("can't read instruction at PC\n");
        }

        // change scno to getpid
        safe_ptrace(PTRACE_SET_SYSCALL, process->tid, 0, (void*)SYS_getpid);
        syshook_arch_syscall_set(state, SYS_getpid);

        // copy new state to process
        safe_ptrace(PTRACE_SETREGS, process->tid, 0, (void*)regs);

        // continue
        safe_ptrace(PTRACE_SYSCALL, process->tid, 0, (void*)0);

        // wait for EXIT
        safe_waitpid(process->tid, &status, __WALL);

        // parse status
        syshook_parse_child_signal(process->tid, status, &parsed_status);

        // verify status
        switch(parsed_status.type) {
            case STATUS_TYPE_SYSCALL:
                // get new state
                syshook_arch_get_state(process, state);
                break;

            default:
                LOGF("invalid status\n");
        }

        // set registers
        safe_ptrace(PTRACE_SETREGS, process->tid, 0, (void*)regs);

        // set back PC
        syshook_arch_set_pc(state, pc - syshook_arch_get_instruction_size(instr));

        // copy new state to process
        safe_ptrace(PTRACE_SETREGS, process->tid, 0, (void*)regs);

        // continue
        safe_ptrace(PTRACE_SYSCALL, process->tid, 0, (void*)0);

        // wait for ENTRY
        safe_waitpid(process->tid, &status, __WALL);

        // parse status
        syshook_parse_child_signal(process->tid, status, &parsed_status);

        // verify status
        switch(parsed_status.type) {
            case STATUS_TYPE_SYSCALL:
                // get new state
                syshook_arch_get_state(process, state);
                break;

            default:
                LOGF("invalid status\n");
        }

        // restore regs
        syshook_arch_syscall_set(state, scno);
        safe_ptrace(PTRACE_SET_SYSCALL, process->tid, 0, (void*)scno);
        syshook_arch_argument_set(state, 0, a0);
    }

    if(pdata->result_changed) {
        regs->ARM_r0 = pdata->result;
    }

    if(pdata->lowargs_changed || pdata->highargs_changed) {
        //LOGD("apply lowregs\n");
        safe_ptrace(PTRACE_SETREGS, process->tid, 0, (void*)regs);
    }

    // reset
    pdata->lowargs_changed = false;
    pdata->highargs_changed = false;
    pdata->scno_changed = false;
    pdata->result_changed = false;
}

bool syshook_arch_is_entry(void* state) {
    syshook_internal_t* pdata = state;
    const struct pt_regs* regs = (void*)pdata->regs;

    return (regs->ARM_ip==0);
}

void syshook_arch_copy_state(void* dst, void* src) {
    memcpy(dst, src, PLATFORM_STATE_SIZE);
}

long syshook_arch_get_pc(void* state) {
    syshook_internal_t* pdata = state;
    const struct pt_regs* regs = (void*)pdata->regs;

    return regs->ARM_pc;
}

void syshook_arch_set_pc(void* state, long pc) {
    syshook_internal_t* pdata = state;
    struct pt_regs* regs = (void*)pdata->regs;

    regs->ARM_pc = pc;
    pdata->lowargs_changed = true;
}

long syshook_arch_get_instruction_size(unsigned long instr) {
    return is_wide_instruction(instr)?4:2;
}

long syshook_arch_syscall_get(void* state) {
    syshook_internal_t* pdata = state;
    const struct pt_regs* regs = (void*)pdata->regs;

    return regs->ARM_r7;
}

void syshook_arch_syscall_set(void* state, long scno) {
    syshook_internal_t* pdata = state;
    struct pt_regs* regs = (void*)pdata->regs;

    regs->ARM_r7 = scno;
    pdata->scno_changed = true;
    pdata->lowargs_changed = true;
}

long syshook_arch_argument_get(void* state, int num) {
    syshook_internal_t* pdata = state;
    const struct pt_regs* regs = (void*)pdata->regs;
    
    switch(num) {
        case 0: return regs->ARM_r0;
        case 1: return regs->ARM_r1;
        case 2: return regs->ARM_r2;
        case 3: return regs->ARM_r3;
        case 4: return regs->ARM_r4;
        case 5: return regs->ARM_r5;
        case 6: return regs->ARM_r6;
        default:
            LOGF("Invalid argument number %d\n", num);
            return -1;
    }
}

void syshook_arch_argument_set(void* state, int num, long value) {
    syshook_internal_t* pdata = state;
    struct pt_regs* regs = (void*)pdata->regs;
    
    switch(num) {
        case 0: regs->ARM_r0 = value; break;
        case 1: regs->ARM_r1 = value; break;
        case 2: regs->ARM_r2 = value; break;
        case 3: regs->ARM_r3 = value; break;
        case 4: regs->ARM_r4 = value; break;
        case 5: regs->ARM_r5 = value; break;
        case 6: regs->ARM_r6 = value; break;
        default:
            LOGF("Invalid argument number %d\n", num);
    }

    if(num<=3) {
        pdata->lowargs_changed = true;
    }
    else {
        pdata->highargs_changed = true;
    }
}

long syshook_arch_result_get(void* state) {
    syshook_internal_t* pdata = state;
    return pdata->result;
}

void syshook_arch_result_set(void* state, long value) {
    syshook_internal_t* pdata = state;

    pdata->result = value;
    pdata->result_changed = true;
}

void syshook_arch_setup_process_trap(syshook_process_t* process) {
    void* fn_template;
    long mem_size;

    // get regs
    syshook_internal_t* pdata = process->state;
    const struct pt_regs* regs = (void*)pdata->regs;

    // get template to use
    if(thumb_mode(regs)){
        fn_template = INJECTION_PTR(inj_trap_thumb);
        mem_size = INJECTION_SIZE(inj_trap_thumb);
    }
    else {
        fn_template = INJECTION_PTR(inj_trap_arm);
        mem_size = INJECTION_SIZE(inj_trap_arm);
    }
    long mem_size_rounded = ROUNDUP(mem_size, process->context->pagesize);;

    // allocate child memory
    void __user *mem = (void*)syshook_invoke_syscall(process, SYS_mmap2, NULL, mem_size_rounded, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if(mem==NULL) {
        LOGF("can't allocate child memory\n");
    }

    // copy inj_trap code
    syshook_copy_to_user(process, mem, fn_template, mem_size);

    // store context data
    process->handler_context[0] = (long)mem;
    process->handler_context[1] = mem_size_rounded;
}
