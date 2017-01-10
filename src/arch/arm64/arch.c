#include <common.h>
#include <syshook/scno.h>

#include <sys/syscall.h>
#include <linux/ptrace.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <linux/elf.h>
#include <inttypes.h>

#ifndef is_wide_instruction
#define is_wide_instruction(instr)      ((unsigned)(instr) >= 0xe800)
#endif

#ifndef thumb_mode
#define thumb_mode(regs) (((regs)->ARM_cpsr & PSR_T_BIT))
#endif

#define PSR_T_BIT	0x00000020
#define PTRACE_SET_SYSCALL	23

#define ARM_cpsr	uregs[16]
#define ARM_pc		uregs[15]
#define ARM_lr		uregs[14]
#define ARM_sp		uregs[13]
#define ARM_ip		uregs[12]
#define ARM_fp		uregs[11]
#define ARM_r10		uregs[10]
#define ARM_r9		uregs[9]
#define ARM_r8		uregs[8]
#define ARM_r7		uregs[7]
#define ARM_r6		uregs[6]
#define ARM_r5		uregs[5]
#define ARM_r4		uregs[4]
#define ARM_r3		uregs[3]
#define ARM_r2		uregs[2]
#define ARM_r1		uregs[1]
#define ARM_r0		uregs[0]
#define ARM_ORIG_r0	uregs[17]

INJECTION_DECLARE(inj_trap_aarch32);
INJECTION_DECLARE(inj_trap_aarch32_thumb);
INJECTION_DECLARE(inj_trap_aarch64);

struct compat_pt_regs {
	int32_t uregs[18];
};

typedef struct {
    bool scno_changed;
    bool result_changed;
    unsigned long long result;
    bool regs_changed;

    union {
        struct compat_pt_regs aarch32;
        struct user_pt_regs aarch64;
    } regs;
    struct iovec iov;
} isyshook_state_t;

typedef struct  {
    long max_scno;
    void **sys_call_table_aarch32;
    void **sys_call_table_aarch64;
} isyshook_pdata_t;

static long syscall_map_aarch32[SYSHOOK_SCNO_MAX] = {
#include <syshook/private/arch/syscall_map_arm.h>
};

static long syscall_map_aarch64[SYSHOOK_SCNO_MAX] = {
#include <syshook/private/arch/syscall_map_arm64.h>
};

static inline __attribute__((always_inline)) long syshook_scno_to_native_internal(long* map, syshook_scno_t scno_generic)
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

static inline __attribute__((always_inline)) int is_compat_task(void* state) {
    isyshook_state_t *istate = state;
    return (istate->iov.iov_len==sizeof(istate->regs.aarch32));
}

void* syshook_arch_init(void) {
    isyshook_pdata_t *pdata = safe_malloc(sizeof(isyshook_pdata_t));

    pdata->max_scno = 512;
    pdata->sys_call_table_aarch32 = safe_calloc(pdata->max_scno, sizeof(void*));
    pdata->sys_call_table_aarch64 = safe_calloc(pdata->max_scno, sizeof(void*));

    return pdata;
}

// START: public API
void syshook_register_syscall_handler(syshook_context_t *context, syshook_scno_t scno_generic, void *handler)
{
    long scno;
    isyshook_pdata_t *pdata = context->archpdata;

    scno = syshook_scno_to_native_internal(syscall_map_aarch32, scno_generic);
    if (scno<0 || scno>=pdata->max_scno) {
        LOGD("Can't register syscall32 handler for %ld: %ld\n", scno_generic, scno);
    }
    pdata->sys_call_table_aarch32[scno] = handler;

    scno = syshook_scno_to_native_internal(syscall_map_aarch64, scno_generic);
    if (scno<0 || scno>=pdata->max_scno) {
        LOGD("Can't register syscall64 handler for %ld: %ld\n", scno_generic, scno);
    }
    pdata->sys_call_table_aarch64[scno] = handler;
}

long syshook_scno_to_native(syshook_process_t *process, syshook_scno_t scno_generic)
{
    if (is_compat_task(process->state))
        return syshook_scno_to_native_internal(syscall_map_aarch32, scno_generic);
    else
        return syshook_scno_to_native_internal(syscall_map_aarch64, scno_generic);
}

void *syshook_mmap(syshook_process_t *process, void *addr, size_t length, int prot, int flags, int fd, off_t pgoff)
{
    if (is_compat_task(process->state)) {
        // since the value is either negative or an unsigned addr, we have to apply some casting magic
        long scno = syshook_scno_to_native_safe(process, SYSHOOK_SCNO_mmap2);
        int32_t retval = (int32_t)syshook_invoke_syscall(process, scno, addr, length, prot, flags, fd, pgoff);
        if (retval<0 && retval>=-process->context->pagesize)
            return (void*)(intptr_t)retval;
        return (void*)(uintptr_t)(uint32_t)retval;
    }
    else {
        long scno = syshook_scno_to_native_safe(process, SYSHOOK_SCNO_mmap);
        return (void*)syshook_invoke_syscall(process, scno, addr, length, prot, flags, fd, pgoff<<12);
    }
}
// END: public API

void* syshook_arch_get_syscall_handler(syshook_process_t *process, long scno)
{
    isyshook_pdata_t *pdata = process->context->archpdata;
    if (scno>=pdata->max_scno)
        return NULL;

    if (is_compat_task(process->state))
        return pdata->sys_call_table_aarch32[scno];
    else
        return pdata->sys_call_table_aarch64[scno];
}

void syshook_arch_get_state(syshook_process_t *process, void *state)
{
    isyshook_state_t *istate = state;

    // get regs
    istate->iov.iov_len = sizeof(istate->regs);
    safe_ptrace(PTRACE_GETREGSET, process->tid, (void *)NT_PRSTATUS, &istate->iov);
    if (istate->iov.iov_len!=sizeof(istate->regs.aarch32) && istate->iov.iov_len!=sizeof(istate->regs.aarch64))
        LOGF("invalid iov_len: %lu\n", istate->iov.iov_len);

    // store return value separately
    istate->result = syshook_arch_argument_get(state, 0);

    // reset
    istate->regs_changed = false;
    istate->scno_changed = false;
    istate->result_changed = false;
}

void syshook_arch_set_state(syshook_process_t *process, void *state)
{
    isyshook_state_t *istate = state;

    if (istate->result_changed) {
        if (is_compat_task(process->state))
            istate->regs.aarch32.ARM_r0 = istate->result;
        else
            istate->regs.aarch64.regs[0] = istate->result;
        istate->regs_changed = true;
    }

    if (istate->regs_changed) {
        //LOGD("apply lowregs\n");
        safe_ptrace(PTRACE_SETREGSET, process->tid, (void *)NT_PRSTATUS, &istate->iov);
    }

    if (istate->scno_changed) {
        //LOGD("apply scno %lld\n", regs->regs[8]);
        int scno;
        struct iovec iov;

        if (is_compat_task(process->state))
            scno = istate->regs.aarch32.ARM_r7;
        else
            scno = istate->regs.aarch64.regs[8];

        iov.iov_base = &scno;
        iov.iov_len = sizeof(scno);
        safe_ptrace(PTRACE_SETREGSET, process->tid, (void *)NT_ARM_SYSTEM_CALL, &iov);
    }

    // reset
    istate->regs_changed = false;
    istate->scno_changed = false;
    istate->result_changed = false;
}

bool syshook_arch_is_entry(void *state)
{
    isyshook_state_t *istate = state;

    if (is_compat_task(state))
        return (istate->regs.aarch32.ARM_ip==0);
    else
        return (istate->regs.aarch64.regs[7]==0);
}

void syshook_arch_init_state(void *state)
{
    isyshook_state_t *istate = state;

    istate->iov.iov_base = &istate->regs;
    istate->iov.iov_len = 0;
}

void syshook_arch_copy_state(void *dst, void *src)
{
    isyshook_state_t *istate_dst = dst;
    isyshook_state_t *istate_src = src;

    memcpy(istate_dst, istate_src, sizeof(isyshook_state_t));
    istate_dst->iov.iov_base = &istate_dst->regs;
}

long syshook_arch_get_state_size(void)
{
    return sizeof(isyshook_state_t);
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

long syshook_arch_get_pc(void *state)
{
    isyshook_state_t *istate = state;

    if (is_compat_task(state))
        return istate->regs.aarch32.ARM_pc;
    else
        return istate->regs.aarch64.pc;
}

void syshook_arch_set_pc(void *state, long pc)
{
    isyshook_state_t *istate = state;

    if (is_compat_task(state))
        istate->regs.aarch32.ARM_pc = pc;
    else
        istate->regs.aarch64.pc = pc;
    istate->regs_changed = true;
}

long syshook_arch_get_instruction_size(void *state, unsigned long instr)
{
    if (is_compat_task(state)) {
        return is_wide_instruction(instr)?4:2;
    }
    else {
        return 4;
    }
}

long syshook_arch_syscall_get(void *state)
{
    isyshook_state_t *istate = state;

    if (is_compat_task(state))
        return istate->regs.aarch32.ARM_r7;
    else
        return istate->regs.aarch64.regs[8];
}

void syshook_arch_syscall_set(void *state, long scno)
{
    isyshook_state_t *istate = state;

    if (is_compat_task(state))
        istate->regs.aarch32.ARM_r7 = scno;
    else
        istate->regs.aarch64.regs[8] = scno;

    istate->scno_changed = true;
    istate->regs_changed = true;
}

long syshook_arch_argument_get(void *state, int num)
{
    isyshook_state_t *istate = state;

    if (is_compat_task(state)) {
        switch (num) {
            case 0:
                return istate->regs.aarch32.ARM_r0;
            case 1:
                return istate->regs.aarch32.ARM_r1;
            case 2:
                return istate->regs.aarch32.ARM_r2;
            case 3:
                return istate->regs.aarch32.ARM_r3;
            case 4:
                return istate->regs.aarch32.ARM_r4;
            case 5:
                return istate->regs.aarch32.ARM_r5;
            case 6:
                return istate->regs.aarch32.ARM_r6;
            default:
                LOGF("Invalid argument number %d\n", num);
                return -1;
        }
    }
    else {
        switch (num) {
            case 0:
                return istate->regs.aarch64.regs[0];
            case 1:
                return istate->regs.aarch64.regs[1];
            case 2:
                return istate->regs.aarch64.regs[2];
            case 3:
                return istate->regs.aarch64.regs[3];
            case 4:
                return istate->regs.aarch64.regs[4];
            case 5:
                return istate->regs.aarch64.regs[5];
            case 6:
                return istate->regs.aarch64.regs[6];
            default:
                LOGF("Invalid argument number %d\n", num);
                return -1;
        }
    }
}

void syshook_arch_argument_set(void *state, int num, long value)
{
    isyshook_state_t *istate = state;

    if (is_compat_task(state)) {
        switch (num) {
            case 0:
                istate->regs.aarch32.ARM_r0 = value;
                break;
            case 1:
                istate->regs.aarch32.ARM_r1 = value;
                break;
            case 2:
                istate->regs.aarch32.ARM_r2 = value;
                break;
            case 3:
                istate->regs.aarch32.ARM_r3 = value;
                break;
            case 4:
                istate->regs.aarch32.ARM_r4 = value;
                break;
            case 5:
                istate->regs.aarch32.ARM_r5 = value;
                break;
            case 6:
                istate->regs.aarch32.ARM_r6 = value;
                break;
            default:
                LOGF("Invalid argument number %d\n", num);
        }
    }
    else {
        switch (num) {
            case 0:
                istate->regs.aarch64.regs[0] = value;
                break;
            case 1:
                istate->regs.aarch64.regs[1] = value;
                break;
            case 2:
                istate->regs.aarch64.regs[2] = value;
                break;
            case 3:
                istate->regs.aarch64.regs[3] = value;
                break;
            case 4:
                istate->regs.aarch64.regs[4] = value;
                break;
            case 5:
                istate->regs.aarch64.regs[5] = value;
                break;
            case 6:
                istate->regs.aarch64.regs[6] = value;
                break;
            default:
                LOGF("Invalid argument number %d\n", num);
        }
    }

    istate->regs_changed = true;
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
    if (is_compat_task(istate)) {
        if (thumb_mode(&istate->regs.aarch32)) {
            fn_template = INJECTION_PTR(inj_trap_aarch32_thumb);
            mem_size = INJECTION_SIZE(inj_trap_aarch32_thumb);
        } else {
            fn_template = INJECTION_PTR(inj_trap_aarch32);
            mem_size = INJECTION_SIZE(inj_trap_aarch32);
        }
    }
    else {
        fn_template = INJECTION_PTR(inj_trap_aarch64);
        mem_size = INJECTION_SIZE(inj_trap_aarch64);
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

void syshook_arch_show_regs_aarch32(void *state)
{
    isyshook_state_t *istate = state;

    unsigned long flags;
    char buf[64];
    const struct compat_pt_regs *regs = &istate->regs.aarch32;

    LOGD("pc : [<%08"PRIx32">]    lr : [<%08"PRIx32">]    psr: %08"PRIx32"\n",
         regs->ARM_pc, regs->ARM_lr, regs->ARM_cpsr);
    LOGD("sp : %08"PRIx32"  ip : %08"PRIx32"  fp : %08"PRIx32"\n",
         regs->ARM_sp, regs->ARM_ip, regs->ARM_fp);
    LOGD("r10: %08"PRIx32"  r9 : %08"PRIx32"  r8 : %08"PRIx32"\n",
         regs->ARM_r10, regs->ARM_r9,
         regs->ARM_r8);
    LOGD("r7 : %08"PRIx32"  r6 : %08"PRIx32"  r5 : %08"PRIx32"  r4 : %08"PRIx32"\n",
         regs->ARM_r7, regs->ARM_r6,
         regs->ARM_r5, regs->ARM_r4);
    LOGD("r3 : %08"PRIx32"  r2 : %08"PRIx32"  r1 : %08"PRIx32"  r0 : %08"PRIx32"\n",
         regs->ARM_r3, regs->ARM_r2,
         regs->ARM_r1, regs->ARM_r0);

    flags = regs->ARM_cpsr;
    buf[0] = flags & PSR_N_BIT ? 'N' : 'n';
    buf[1] = flags & PSR_Z_BIT ? 'Z' : 'z';
    buf[2] = flags & PSR_C_BIT ? 'C' : 'c';
    buf[3] = flags & PSR_V_BIT ? 'V' : 'v';
    buf[3] = flags & PSR_T_BIT ? 'T' : 't';
    buf[4] = '\0';

    LOGD("xPSR: %08"PRIx32" Flags: %s\n", regs->ARM_cpsr, buf);
    LOGD("\n");
}

void syshook_arch_show_regs_aarch64(void *state)
{
    int i, top_reg;
    uint64_t lr, sp;
    isyshook_state_t *istate = state;
    const struct user_pt_regs *regs = &istate->regs.aarch64;
    char buf[64];

    lr = regs->regs[30];
    sp = regs->sp;
    top_reg = 29;

    LOGD("pc : [<%016llx>] lr : [<%016lx>] pstate: %08llx\n",
         regs->pc, lr, regs->pstate);
    LOGD("sp : %016lx\n", sp);

    i = top_reg;

    while (i >= 0) {
        char *bufptr = buf;
        size_t bufsz = sizeof(buf);
        int ret;

        ret = snprintf(bufptr, bufsz, "x%-2d: %016llx ", i, regs->regs[i]);
        if (ret>=0) {
            bufptr += ret;
            bufsz  -= ret;
        }
        i--;

        if (i % 2 == 0) {
            snprintf(bufptr, bufsz, "x%-2d: %016llx ", i, regs->regs[i]);
            i--;
        }

        LOGD("%s\n", buf);
    }
    LOGD("\n");
}

void syshook_arch_show_regs(void *state)
{
    isyshook_state_t *istate = state;
    LOGD("changed: %s %s %s\n", istate->scno_changed?"scno":"", istate->result_changed?"ret":"", istate->regs_changed?"regs":"");
    LOGD("result: %016llx\n", istate->result);

    if (is_compat_task(state))
        syshook_arch_show_regs_aarch32(state);
    else
        syshook_arch_show_regs_aarch64(state);
}
