#include <common.h>

#include <sys/syscall.h>
#include <linux/ptrace.h>

#ifndef is_wide_instruction
#define is_wide_instruction(instr)      ((unsigned)(instr) >= 0xe800)
#endif

void syshook_arch_get_state(pid_t pid, void* state) {
    syshook_internal_t* pdata = state;
    struct pt_regs* regs = (void*)pdata->regs;

    safe_ptrace(PTRACE_GETREGS, pid, 0, regs);

    // reset
    pdata->lowargs_changed = false;
    pdata->highargs_changed = false;
    pdata->scno_changed = false;
}

void syshook_arch_set_state(pid_t pid, void* state) {
    syshook_internal_t* pdata = state;
    const struct pt_regs* regs = (void*)pdata->regs;

    if(pdata->scno_changed) {
        //LOGD("apply scno\n");
        safe_ptrace(PTRACE_SET_SYSCALL, pid, 0, (void*)regs->ARM_r7);
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
        if(syshook_copy_from_user_internal(pid, &instr, (void*)pc, sizeof(instr))) {
            LOGE("can't read instruction at PC\n");
            safe_exit(-1);
        }

        // change scno to getpid
        safe_ptrace(PTRACE_SET_SYSCALL, pid, 0, (void*)SYS_getpid);
        syshook_arch_syscall_set(state, SYS_getpid);

        // copy new state to process
        safe_ptrace(PTRACE_SETREGS, pid, 0, (void*)regs);

        // continue
        safe_ptrace(PTRACE_SYSCALL, pid, 0, (void*)0);

        // wait for EXIT
        safe_waitpid(pid, &status, __WALL);

        // parse status
        syshook_parse_child_signal(pid, status, &parsed_status);

        // verify status
        switch(parsed_status.type) {
            case STATUS_TYPE_SYSCALL:
                // get new state
                syshook_arch_get_state(pid, state);
                break;

            default:
                LOGE("invalid status\n");
                safe_exit(-1);
        }

        // set registers
        safe_ptrace(PTRACE_SETREGS, pid, 0, (void*)regs);

        // set back PC
        syshook_arch_set_pc(state, pc - syshook_arch_get_instruction_size(instr));

        // copy new state to process
        safe_ptrace(PTRACE_SETREGS, pid, 0, (void*)regs);

        // continue
        safe_ptrace(PTRACE_SYSCALL, pid, 0, (void*)0);

        // wait for ENTRY
        safe_waitpid(pid, &status, __WALL);

        // parse status
        syshook_parse_child_signal(pid, status, &parsed_status);

        // verify status
        switch(parsed_status.type) {
            case STATUS_TYPE_SYSCALL:
                // get new state
                syshook_arch_get_state(pid, state);
                break;

            default:
                LOGE("invalid status\n");
                safe_exit(-1);
        }

        // restore regs
        syshook_arch_syscall_set(state, scno);
        safe_ptrace(PTRACE_SET_SYSCALL, pid, 0, (void*)scno);
        syshook_arch_argument_set(state, 0, a0);
    }

    if(pdata->lowargs_changed || pdata->highargs_changed) {
        //LOGD("apply lowregs\n");
        safe_ptrace(PTRACE_SETREGS, pid, 0, (void*)regs);
    }

    // reset
    pdata->lowargs_changed = false;
    pdata->highargs_changed = false;
    pdata->scno_changed = false;
}

bool syshook_arch_is_entry(void* state) {
    syshook_internal_t* pdata = state;
    const struct pt_regs* regs = (void*)pdata->regs;

    return (regs->ARM_ip==0);
}

void syshook_arch_copy_state(void* dst, void* src) {
    memcpy(dst, src, PLATFORM_STATE_SIZE);
}

/*void* syshook_duplicate_state(void* state) {
    void* mem = safe_malloc(PLATFORM_STATE_SIZE);
    syshook_copy_state(mem, state);
    return mem;
}*/

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

int syshook_arch_syscall_get(void* state) {
    syshook_internal_t* pdata = state;
    const struct pt_regs* regs = (void*)pdata->regs;

    return regs->ARM_r7;
}

void syshook_arch_syscall_set(void* state, int scno) {
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
            LOGE("Invalid argument number %d\n", num);
            safe_exit(-1);
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
            LOGE("Invalid argument number %d\n", num);
            safe_exit(-1);
    }

    if(num<=3) {
        pdata->lowargs_changed = true;
    }
    else {
        pdata->highargs_changed = true;
    }
}

long syshook_arch_result_get(void* state) {
    return syshook_arch_argument_get(state, 0);
}

void syshook_arch_result_set(void* state, long value) {
    syshook_internal_t* pdata = state;

    syshook_arch_argument_set(state, 0, value);
    pdata->result_changed = true;
}
