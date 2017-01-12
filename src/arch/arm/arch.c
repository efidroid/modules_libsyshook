#include <common.h>
#include <syshook/scno.h>

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

typedef struct {
    bool lowargs_changed;
    bool highargs_changed;
    bool scno_changed;
    bool result_changed;
    long result;
    struct pt_regs regs;
} isyshook_state_t;

typedef struct  {
    long max_scno;
    void **sys_call_table;
} isyshook_pdata_t;

static long syscall_map_arm[SYSHOOK_SCNO_MAX] = {
#include <syshook/private/arch/syscall_map_arm.h>
};

static inline __attribute__((always_inline)) long syshook_scno_to_native_internal(long *map, syshook_scno_t scno_generic)
{
    if (scno_generic<0 || scno_generic>=SYSHOOK_SCNO_MAX) {
        return -EINVAL;
    }

    long scno = map[scno_generic];
    if (scno<0) {
        return -ENOSYS;
    }

    return scno;
}

void *syshook_arch_init(void)
{
    isyshook_pdata_t *pdata = safe_malloc(sizeof(isyshook_pdata_t));

    pdata->max_scno = 512;
    pdata->sys_call_table = safe_calloc(pdata->max_scno, sizeof(void *));

    return pdata;
}

// START: public API
void syshook_register_syscall_handler(syshook_context_t *context, syshook_scno_t scno_generic, void *handler)
{
    isyshook_pdata_t *pdata = context->archpdata;

    long scno = syshook_scno_to_native_internal(syscall_map_arm, scno_generic);
    if (scno>=pdata->max_scno) {
        LOGD("Can't register syscall handler for %ld: %ld\n", scno_generic, scno);
    }
    pdata->sys_call_table[scno] = handler;
}

long syshook_scno_to_native(syshook_process_t *process, syshook_scno_t scno_generic)
{
    (void)(process);
    return syshook_scno_to_native_internal(syscall_map_arm, scno_generic);
}

void *syshook_mmap(syshook_process_t *process, void *addr, size_t length, int prot, int flags, int fd, off_t pgoff)
{
    long scno = syshook_scno_to_native_safe(process, SYSHOOK_SCNO_mmap2);
    return (void *)syshook_invoke_syscall(process, scno, addr, length, prot, flags, fd, pgoff);
}
// END: public API

void *syshook_arch_get_syscall_handler(syshook_process_t *process, long scno)
{
    isyshook_pdata_t *pdata = process->context->archpdata;
    if (scno>=pdata->max_scno)
        return NULL;

    return pdata->sys_call_table[scno];
}

void syshook_arch_get_state(syshook_process_t *process, void *state)
{
    isyshook_state_t *istate = state;

    // get regs
    safe_ptrace(PTRACE_GETREGS, process->tid, 0, &istate->regs);

    // store return value separately
    istate->result = syshook_arch_argument_get(state, 0);

    // reset
    istate->lowargs_changed = false;
    istate->highargs_changed = false;
    istate->scno_changed = false;
    istate->result_changed = false;
}

void syshook_arch_set_state(syshook_process_t *process, void *state)
{
    isyshook_state_t *istate = state;
    struct pt_regs *regs = &istate->regs;

    if (istate->scno_changed) {
        //LOGD("apply scno\n");
        safe_ptrace(PTRACE_SET_SYSCALL, process->tid, 0, (void *)regs->ARM_r7);
    }

    if (istate->highargs_changed && syshook_arch_is_entry(state)) {
        //LOGD("apply highregs\n");

        parsed_status_t parsed_status;

        // backup regs
        int scno = syshook_arch_syscall_get(state);
        long a0 = syshook_arch_argument_get(state, 0);

        // get pc and instruction
        unsigned long instr;
        long pc = syshook_arch_get_pc(state);
        if (syshook_copy_from_user(process, &instr, (void *)pc, sizeof(instr))) {
            LOGF("can't read instruction at PC\n");
        }

        // change scno to getpid
        long scno_getpid = syshook_scno_to_native(process, SYSHOOK_SCNO_getpid);
        safe_ptrace(PTRACE_SET_SYSCALL, process->tid, 0, (void *)scno_getpid);
        syshook_arch_syscall_set(state, scno_getpid);

        // copy new state to process
        safe_ptrace(PTRACE_SETREGS, process->tid, 0, (void *)regs);

        // continue
        safe_ptrace(PTRACE_SYSCALL, process->tid, 0, (void *)0);

        // wait for EXIT
        syshook_handle_child_signals(process, &parsed_status, STATUS_TYPE_SYSCALL);

        // get new state
        syshook_arch_get_state(process, state);

        // set registers
        safe_ptrace(PTRACE_SETREGS, process->tid, 0, (void *)regs);

        // set back PC
        syshook_arch_set_pc(state, pc - syshook_arch_get_instruction_size(state, instr));

        // copy new state to process
        safe_ptrace(PTRACE_SETREGS, process->tid, 0, (void *)regs);

        // continue
        safe_ptrace(PTRACE_SYSCALL, process->tid, 0, (void *)0);

        // wait for ENTRY
        syshook_handle_child_signals(process, &parsed_status, STATUS_TYPE_SYSCALL);

        // get new state
        syshook_arch_get_state(process, state);

        // restore regs
        syshook_arch_syscall_set(state, scno);
        safe_ptrace(PTRACE_SET_SYSCALL, process->tid, 0, (void *)scno);
        syshook_arch_argument_set(state, 0, a0);
    }

    if (istate->result_changed) {
        regs->ARM_r0 = istate->result;
        istate->lowargs_changed = true;
    }

    if (istate->lowargs_changed || istate->highargs_changed) {
        //LOGD("apply lowregs\n");
        safe_ptrace(PTRACE_SETREGS, process->tid, 0, (void *)regs);
    }

    // reset
    istate->lowargs_changed = false;
    istate->highargs_changed = false;
    istate->scno_changed = false;
    istate->result_changed = false;
}

void syshook_arch_copy_state_diffs(void *dst, void *src)
{
    isyshook_state_t *istate_dst = dst;
    isyshook_state_t *istate_src = src;

    // restore scno
    // scno is stored in one of the args, so do this before restoring them
    long scno_now = syshook_arch_syscall_get(dst);
    long scno_backup = syshook_arch_syscall_get(src);
    if (scno_now!=scno_backup) {
        syshook_arch_syscall_set(dst, scno_backup);
    }

    // restore arguments
    int i;
    for (i=0; i<=6; i++) {
        long val = syshook_arch_argument_get(dst, i);
        long val_backup = syshook_arch_argument_get(src, i);
        if (val!=val_backup) {
            syshook_arch_argument_set(dst, i, val_backup);
        }
    }

    // restore result
    long rc_now = syshook_arch_result_get(dst);
    long rc_backup = syshook_arch_result_get(src);
    if (rc_now!=rc_backup) {
        syshook_arch_result_set(dst, rc_backup);
    }
    istate_dst->result_changed = istate_src->result_changed;
}

bool syshook_arch_is_entry(void *state)
{
    isyshook_state_t *istate = state;

    return (istate->regs.ARM_ip==0);
}

void syshook_arch_init_state(void *state)
{
    (void)(state);
}

void syshook_arch_copy_state(void *dst, void *src)
{
    memcpy(dst, src, sizeof(isyshook_state_t));
}

long syshook_arch_get_state_size(void)
{
    return sizeof(isyshook_state_t);
}

long syshook_arch_get_pc(void *state)
{
    isyshook_state_t *istate = state;
    return istate->regs.ARM_pc;
}

void syshook_arch_set_pc(void *state, long pc)
{
    isyshook_state_t *istate = state;

    istate->regs.ARM_pc = pc;
    istate->lowargs_changed = true;
}

long syshook_arch_get_instruction_size(void *state, unsigned long instr)
{
    (void)(state);
    return is_wide_instruction(instr)?4:2;
}

long syshook_arch_syscall_get(void *state)
{
    isyshook_state_t *istate = state;
    return istate->regs.ARM_r7;
}

void syshook_arch_syscall_set(void *state, long scno)
{
    isyshook_state_t *istate = state;

    istate->regs.ARM_r7 = scno;
    istate->scno_changed = true;
    istate->lowargs_changed = true;
}

long syshook_arch_argument_get(void *state, int num)
{
    isyshook_state_t *istate = state;
    const struct pt_regs *regs = &istate->regs;

    switch (num) {
        case 0:
            return regs->ARM_r0;
        case 1:
            return regs->ARM_r1;
        case 2:
            return regs->ARM_r2;
        case 3:
            return regs->ARM_r3;
        case 4:
            return regs->ARM_r4;
        case 5:
            return regs->ARM_r5;
        case 6:
            return regs->ARM_r6;
        default:
            LOGF("Invalid argument number %d\n", num);
            return -1;
    }
}

void syshook_arch_argument_set(void *state, int num, long value)
{
    isyshook_state_t *istate = state;
    struct pt_regs *regs = &istate->regs;

    switch (num) {
        case 0:
            regs->ARM_r0 = value;
            break;
        case 1:
            regs->ARM_r1 = value;
            break;
        case 2:
            regs->ARM_r2 = value;
            break;
        case 3:
            regs->ARM_r3 = value;
            break;
        case 4:
            regs->ARM_r4 = value;
            break;
        case 5:
            regs->ARM_r5 = value;
            break;
        case 6:
            regs->ARM_r6 = value;
            break;
        default:
            LOGF("Invalid argument number %d\n", num);
    }

    if (num<=3) {
        istate->lowargs_changed = true;
    } else {
        istate->highargs_changed = true;
    }
}

long syshook_arch_result_get(void *state)
{
    isyshook_state_t *istate = state;
    return istate->result;
}

void syshook_arch_result_set(void *state, long value)
{
    isyshook_state_t *istate = state;

    istate->result = value;
    istate->result_changed = true;
}

void syshook_arch_setup_process_trap(syshook_process_t *process)
{
    void *fn_template;
    long mem_size;
    isyshook_state_t *istate = process->state;

    // get template to use
    if (thumb_mode(&istate->regs)) {
        fn_template = INJECTION_PTR(inj_trap_thumb);
        mem_size = INJECTION_SIZE(inj_trap_thumb);
    } else {
        fn_template = INJECTION_PTR(inj_trap_arm);
        mem_size = INJECTION_SIZE(inj_trap_arm);
    }

    // roundup size
    long mem_size_rounded = ROUNDUP(mem_size, process->context->pagesize);

    // allocate child memory
    void __user *mem = syshook_mmap(process, NULL, mem_size_rounded, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if ((long)mem<0 && (long)mem>=-process->context->pagesize) {
        LOGF("can't allocate child memory %ld %p\n", (long)mem, mem);
    }

    // copy inj_trap code
    syshook_copy_to_user(process, mem, fn_template, mem_size);

    // store context data
    process->trap_mem = mem;
    process->trap_size = mem_size_rounded;
}

void syshook_arch_show_regs(void *state)
{
    isyshook_state_t *istate = state;

    unsigned long flags;
    char buf[64];
    const struct pt_regs *regs = &istate->regs;

    LOGD("pc : [<%08lx>]    lr : [<%08lx>]    psr: %08lx\n",
         regs->ARM_pc, regs->ARM_lr, regs->ARM_cpsr);
    LOGD("sp : %08lx  ip : %08lx  fp : %08lx\n",
         regs->ARM_sp, regs->ARM_ip, regs->ARM_fp);
    LOGD("r10: %08lx  r9 : %08lx  r8 : %08lx\n",
         regs->ARM_r10, regs->ARM_r9,
         regs->ARM_r8);
    LOGD("r7 : %08lx  r6 : %08lx  r5 : %08lx  r4 : %08lx\n",
         regs->ARM_r7, regs->ARM_r6,
         regs->ARM_r5, regs->ARM_r4);
    LOGD("r3 : %08lx  r2 : %08lx  r1 : %08lx  r0 : %08lx\n",
         regs->ARM_r3, regs->ARM_r2,
         regs->ARM_r1, regs->ARM_r0);

    flags = regs->ARM_cpsr;
    buf[0] = flags & PSR_N_BIT ? 'N' : 'n';
    buf[1] = flags & PSR_Z_BIT ? 'Z' : 'z';
    buf[2] = flags & PSR_C_BIT ? 'C' : 'c';
    buf[3] = flags & PSR_V_BIT ? 'V' : 'v';
    buf[3] = flags & PSR_T_BIT ? 'T' : 't';
    buf[4] = '\0';

    LOGD("xPSR: %08lx Flags: %s\n", regs->ARM_cpsr, buf);
    LOGD("\n");
}
