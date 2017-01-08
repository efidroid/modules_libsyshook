/*
 * Copyright 2016, The EFIDroid Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#include <fcntl.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <sys/mman.h>

#include <common.h>
#include <syshook.h>

static void syshook_parse_child_signal(pid_t tid, int status, parsed_status_t *pstatus);

static __thread syshook_process_t *thread_process = NULL;

static void syshook_continue(syshook_process_t *process, int signal)
{
    safe_ptrace(PTRACE_SYSCALL, process->tid, 0, (void *)signal);
}

static void syshook_wait_for_signal(syshook_process_t *process, parsed_status_t *parsed_status)
{
    int status = 0;

    // wait for signal
    pid_t ret = safe_waitpid(process->tid, &status, __WALL);

    if (ret!=process->tid) {
        LOGF("got status from wrong process\n");
    }

    // parse status
    syshook_parse_child_signal(process->tid, status, parsed_status);
}

syshook_process_t *get_process_by_tid(syshook_context_t *context, pid_t tid)
{
    pthread_mutex_lock(&context->lock);
    syshook_process_t *entry;
    list_for_every_entry(&context->processes, entry, syshook_process_t, node) {
        if (entry->tid==tid) {
            pthread_mutex_unlock(&context->lock);
            return entry;
        }
    }
    pthread_mutex_unlock(&context->lock);

    return NULL;
}

syshook_process_t *get_thread_process(void)
{
    if (!thread_process) {
        LOGF("thread_process is not set\n");
    }
    return thread_process;
}

void syshook_thread_exit(int code)
{
    syshook_process_t *process = get_thread_process();
    longjmp(process->jmpbuf, code);
}

clone_flags_entry_t *syshook_get_clone_flags_entry(syshook_process_t *process, pid_t pid)
{
    clone_flags_entry_t *entry;
    list_for_every_entry(&process->clone_flags_list, entry, clone_flags_entry_t, node) {
        if (entry->pid==pid)
            return entry;
    }

    return NULL;
}

static syshook_process_t *syshook_handle_new_process(syshook_context_t *context, pid_t pid, pid_t tid, pid_t ppid, pid_t cpid)
{
    syshook_process_t *process;

    process = safe_calloc(1, sizeof(syshook_process_t));
    process->context = context;
    process->pid = pid;
    process->tid = tid;
    process->ppid = ppid;
    process->creatorpid = cpid;
    process->original_state = safe_calloc(1, syshook_arch_get_state_size());
    process->state = safe_calloc(1, syshook_arch_get_state_size());
    process->sigstop_received = false;
    pthread_mutex_init(&process->lock, NULL);
    pthread_mutex_init(&process->clone_flags_lock, NULL);
    list_initialize(&process->clone_flags_list);
    syshook_arch_init_state(process->original_state);
    syshook_arch_init_state(process->state);

    pthread_mutex_lock(&context->lock);
    list_add_tail(&context->processes, &process->node);
    pthread_mutex_unlock(&context->lock);

    LOGD("new process pid=%d tid=%d ppid=%d cpid=%d\n", pid, tid, ppid, cpid);

    return process;
}

static void syshook_delete_process(syshook_process_t *process)
{
    LOGD("stopped %d\n", process->tid);

    if (process->context->destroy_process) {
        int rc = process->context->destroy_process(process);
        if (rc) {
            LOGF("error in destroy_process\n");
        }
    }

    pthread_mutex_lock(&process->context->lock);
    list_delete(&process->node);
    pthread_mutex_unlock(&process->context->lock);

    free(process->state);
    free(process->original_state);
    free(process);
}

static long syshook_invoke_syscall_handler(syshook_process_t *process, long scno)
{
    long (*fn)(syshook_process_t *, ...);

    if (process->exit_handler) {
        fn = process->exit_handler;
        process->exit_handler = NULL;
    }

    else {
        if (scno>=SYSHOOK_NUM_SYSCALLS || !process->context->sys_call_table[scno])
            return -1;

        fn = process->context->sys_call_table[scno];
    }

    long a0 = syshook_arch_argument_get(process->state, 0);
    long a1 = syshook_arch_argument_get(process->state, 1);
    long a2 = syshook_arch_argument_get(process->state, 2);
    long a3 = syshook_arch_argument_get(process->state, 3);
    long a4 = syshook_arch_argument_get(process->state, 4);
    long a5 = syshook_arch_argument_get(process->state, 5);
    long a6 = syshook_arch_argument_get(process->state, 6);

    return fn(process, a0, a1, a2, a3, a4, a5, a6);
}

static void syshook_copy_state_diffs(void *dst, void *src)
{
    // restore arguments
    int i;
    for (i=0; i<=6; i++) {
        long val = syshook_arch_argument_get(dst, i);
        long val_backup = syshook_arch_argument_get(src, i);
        if (val!=val_backup) {
            syshook_arch_argument_set(dst, i, val_backup);
        }
    }

    // restore scno
    long scno_now = syshook_arch_syscall_get(dst);
    long scno_backup = syshook_arch_syscall_get(src);
    if (scno_now!=scno_backup) {
        syshook_arch_syscall_set(dst, scno_backup);
    }

    // restore result
    long rc_now = syshook_arch_result_get(dst);
    long rc_backup = syshook_arch_result_get(src);
    if (rc_now!=rc_backup) {
        syshook_arch_result_set(dst, rc_backup);
    }
}

static int syshook_handle_child_syscall(syshook_process_t *process)
{
    // get current state
    syshook_arch_get_state(process, process->original_state);

    // copy state so we can modify it and still have a copy
    syshook_arch_copy_state(process->state, process->original_state);

    long scno = syshook_arch_syscall_get(process->state);
    bool is_entry = syshook_arch_is_entry(process->state);
    bool force_copy_state = false;

    //LOGD("[%d:%d][SYSCALL][%s] %ld\n", process->pid, process->tid, is_entry?"ENTRY":"EXIT", scno);

    if (process->expect_execve) {
        if (scno==SYS_execve) {
            // execve returned due to an error
            process->expect_syscall_exit = true;
            process->expect_execve = false;
        } else
            LOGF("execve did not happen\n");
    }

    // this call will not have an exit, continue
    if (!is_entry && scno==SYS_restart_syscall) {
        return 0;
    }

    // the syscall had no handler and got ignored
    if (!is_entry && process->expect_syscall_exit) {
        process->expect_syscall_exit = false;
        return 0;
    }

    if (!is_entry && !process->exit_handler) {
        LOGF("received exit but no exit handler is set\n");
    }

    // apparently, the exit did not happen
    if (is_entry) {
        process->expect_syscall_exit = false;
        process->exit_handler = NULL;

        if (process->trap_mem && process->sigstop_received) {
            long ret = syshook_invoke_syscall(process, SYS_munmap, process->trap_mem, process->trap_size);
            // free up trap memory
            if (ret)
                LOGF("can't munmap process trap in child: %d\n", (int)ret);

            process->trap_mem = NULL;
            process->trap_size = 0;
            force_copy_state = true;
        }
    }

    long ret = -1;
    bool handler_exists = (scno<SYSHOOK_NUM_SYSCALLS && process->context->sys_call_table[scno]) || process->exit_handler;
    if (handler_exists) {
        ret = syshook_invoke_syscall_handler(process, scno);

        // call handler again later if/when the syscall returns
        if (process->exit_handler) {
            if (!syshook_arch_is_entry(process->state)) {
                LOGF("exit_handler is set, but process is in exit state already");
            }

            // copy new state to process
            syshook_arch_set_state(process, process->state);
            return 0;
        }

        // the handler didn't call the original function, so convert the call to getpid
        is_entry = syshook_arch_is_entry(process->state);
        if (is_entry) {
            syshook_arch_syscall_set(process->state, SYS_getpid);
            syshook_invoke_hookee(process);
        }
    }

    else {
        if (force_copy_state) {
            // copy new state to process
            syshook_arch_set_state(process, process->state);
        }

        // ignore this call
        process->expect_syscall_exit = true;

        // check if this is execve
        if (is_entry && scno==SYS_execve)
            process->expect_execve = true;

        return 0;
    }

    // update status
    is_entry = syshook_arch_is_entry(process->state);
    scno = syshook_arch_syscall_get(process->state);

    // make sure we leave this function with the child in EXIT
    if (is_entry) {
        LOGF("we're still in entry state\n");
    }

    // execve returned due to an error from within a syscall handler
    if (scno==SYS_execve) {
        process->expect_execve = false;
    }

    // restore state
    syshook_copy_state_diffs(process->state, process->original_state);

    // set return value
    // this makes sure that set_state uses the result cache instead of the r0 register value
    // also, we want to use whatever the handler returned instead of the real return value
    syshook_arch_result_set(process->state, ret);

    // copy new state to process
    syshook_arch_set_state(process, process->state);

    process->exit_handler = NULL;

    return 0;
}

void notify_execve_threads(syshook_context_t *context)
{
    pthread_mutex_lock(&context->lock);
    syshook_process_t *entry;
    list_for_every_entry(&context->processes, entry, syshook_process_t, node) {
        if (entry->expect_execve) {
            kill(entry->thread_tid, SIGUSR1);
        }
    }
    pthread_mutex_unlock(&context->lock);
}

static void syshook_parse_child_signal(pid_t tid, int status, parsed_status_t *pstatus)
{
    int signal = 0;

    if (WIFEXITED(status)) {
        signal = WEXITSTATUS(status);
        LOGD("[%d] exit with %d\n", tid, signal);
        pstatus->type = STATUS_TYPE_EXIT;
    }

    else if (WIFSIGNALED(status)) {
        signal = WTERMSIG(status);
        LOGD("[%d] received %s\n", tid, sig2str(signal));
        pstatus->type = STATUS_TYPE_EXIT;
    }

    else if (WIFSTOPPED(status)) {
        signal = WSTOPSIG(status);
        int event = status>>16;

        if (signal == (SIGTRAP|0x80)) {
            pstatus->type = STATUS_TYPE_SYSCALL;
            signal = 0;
        }

        else if (signal==SIGTRAP) {
            siginfo_t siginfo;
            unsigned long data;

            switch (event) {
                case PTRACE_EVENT_VFORK:
                case PTRACE_EVENT_FORK:
                case PTRACE_EVENT_CLONE:
                    safe_ptrace(PTRACE_GETEVENTMSG, tid, NULL, &data);
                    LOGD("[%d][TRAP] event=%s clone_pid=%d\n", tid, ptraceevent2str(event), (pid_t)data);

                    signal = 0;
                    pstatus->type = STATUS_TYPE_CLONE;
                    pstatus->data = data;
                    break;

                case PTRACE_EVENT_EXEC:
                    if (safe_ptrace_ex(PTRACE_GETEVENTMSG, tid, NULL, &data, 1)==-1) {
                        signal = 0;
                        pstatus->type = STATUS_TYPE_EXEC_OTHER;
                        pstatus->data = 0;
                    } else {
                        signal = 0;
                        pstatus->type = STATUS_TYPE_EXEC;
                        pstatus->data = data;
                    }
                    LOGD("[%d][TRAP] event=%s caller=%d\n", tid, ptraceevent2str(event), (pid_t)data);
                    break;

                default:
                    safe_ptrace(PTRACE_GETSIGINFO, tid, NULL, &siginfo);

                    if (siginfo.si_code==SI_KERNEL || siginfo.si_code<=0) {
                        pstatus->type = STATUS_TYPE_OTHER;

                        // this happens after execve if PTRACE_O_TRACEEXEC is disabled
                        if (siginfo.si_code==SI_USER) {
                            signal = 0;
                        }
                    } else {
                        LOGF("[%d][TRAP] unknown event: %s(%d)\n", tid, ptraceevent2str(event), event);
                    }
            }
        }

        if (signal!=0) {
            pstatus->type = STATUS_TYPE_OTHER;
            LOGD("[%d] stopped with %s 0x%08x\n", tid, sig2str(signal), signal);
        }
    }

    else if (WIFCONTINUED(status)) {
        LOGD("[%d] continued\n", tid);
        pstatus->type = STATUS_TYPE_OTHER;
    }

    else {
        LOGF("[%d] unknown status 0x%x\n", tid, status);
    }

    pstatus->signal = signal;
}

static void thread_usr1_handler(int sig, siginfo_t *info, void *vp)
{
    (void)(sig);
    (void)(info);
    (void)(vp);

    syshook_process_t *process = get_thread_process();
    siglongjmp (process->sigjmpbuf, 1);
}

static int util_setsighandler(int signum, void (*handler)(int, siginfo_t *, void *))
{
    struct sigaction usr_action;
    sigset_t block_mask;
    int rc;

    rc = sigfillset (&block_mask);
    if (rc) {
        return rc;
    }

    usr_action.sa_sigaction = handler;
    usr_action.sa_mask = block_mask;
    usr_action.sa_flags = SA_SIGINFO;
    return sigaction(signum, &usr_action, NULL);
}

static void *syshook_child_thread(void *pdata)
{
    syshook_process_t *process = pdata;
    parsed_status_t parsed_status;

    thread_process = process;
    process->thread_tid = (pid_t)syscall(SYS_gettid);
    util_setsighandler(SIGUSR1, thread_usr1_handler);

    int rc = setjmp(process->jmpbuf);
    if (rc) {
        if (rc==THREAD_EXIT_CODE_EXEC)
            goto mainloop;

        goto stopthread;
    }

    if (process->is_root_process) {
        // continue child
        syshook_continue(process, 0);
    } else {
        // attach to process
        safe_ptrace(PTRACE_ATTACH, process->tid, 0, (void *)0);
    }

    rc = sigsetjmp (process->sigjmpbuf, 1);
    if (rc) {
        // get event message
        unsigned long data;
        safe_ptrace(PTRACE_GETEVENTMSG, process->pid, NULL, &data);
        LOGV("execve. we're the thread leader now\n");

        if (process->context->execve_process) {
            rc = process->context->execve_process(process);
            if (rc) {
                LOGF("error in execve_process\n");
            }
        }

        // update process state
        process->tid = process->pid;
        process->expect_execve = false;
        if (process->tid==process->context->roottid) {
            process->is_root_process = true;
            LOGV("we're the root process now too\n");
        }

        // continue
        syshook_continue(process, 0);
    }

mainloop:
    // main loop
    syshook_handle_child_signals(process, &parsed_status, 0);

stopthread:
    if (rc<=0)
        LOGF("exited in a unexpected way\n");

    if (process->is_root_process && rc!=THREAD_EXIT_CODE_EXEC_OTHER) {
        pthread_mutex_lock(&process->context->exit_mutex);
        process->context->do_exit = rc;
        pthread_cond_signal(&process->context->exit_cond);
        pthread_mutex_unlock(&process->context->exit_mutex);
    }

    syshook_delete_process(process);

    return NULL;
}

static void syshook_handle_new_clone(syshook_context_t *context, syshook_process_t *creator, pid_t clone_tid)
{
    int rc;
    parsed_status_t parsed_status;
    clone_flags_entry_t *entry;

    // register process
    long clone_flags;
    pid_t clone_pid = clone_tid;
    pid_t clone_ppid = creator->pid;

    pthread_mutex_lock(&creator->clone_flags_lock);

    // get clone flags entry
    entry = syshook_get_clone_flags_entry(creator, clone_tid);
    if (!entry) {
        entry = syshook_get_clone_flags_entry(creator, 0);
    }
    if (!entry) {
        LOGF("can't find clone_flags entry\n");
    }

    // get clone_flags and remove entry from list
    clone_flags = entry->clone_flags;
    list_delete(&entry->node);

    pthread_mutex_unlock(&creator->clone_flags_lock);

    if (clone_flags&CLONE_THREAD) {
        clone_pid = creator->pid;
    }

    if ((clone_flags&CLONE_PARENT) || (clone_flags&CLONE_THREAD)) {
        clone_ppid = creator->ppid;
    }

    syshook_process_t *process = syshook_handle_new_process(context, clone_pid, clone_tid, clone_ppid, creator->tid);
    process->clone_flags = clone_flags;
    process->trap_mem = entry->trap_mem;
    process->trap_size = entry->trap_size;

    // free clone entry
    free(entry);

    // run callback
    if (context->create_process) {
        rc = context->create_process(process);
        if (rc) {
            LOGF("error in create_process\n");
        }
    }

    // wait for SIGSTOP
    syshook_wait_for_signal(process, &parsed_status);
    if (!(parsed_status.type==STATUS_TYPE_OTHER && parsed_status.signal==SIGSTOP)) {
        syshook_thread_exit(THREAD_EXIT_CODE_ERROR);
    }

    // get state
    syshook_arch_get_state(process, process->state);

    // set PC
    process->handler_context[0] = syshook_arch_get_pc(process->state);
    syshook_arch_set_pc(process->state, (long) process->trap_mem);

    // apply state
    syshook_arch_set_state(process, process->state);

    // detach
    safe_ptrace(PTRACE_DETACH, process->tid, 0, 0);

    // attr init
    pthread_attr_t attr;
    rc = pthread_attr_init(&attr);
    if (rc) {
        LOGF("can't initialize pthread attributes: %s\n", strerror(rc));
    }

    // detached state
    rc = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (rc) {
        LOGF("can't set detached state attribute: %s\n", strerror(rc));
    }

    // start thread
    rc = pthread_create(&(process->thread), &attr, syshook_child_thread, process);
    if (rc) {
        LOGF("can't create pthread: %s\n", strerror(rc));
    }

    // cleanup
    pthread_attr_destroy(&attr);
}

void syshook_stop_tracing(syshook_process_t *process)
{
    safe_ptrace(PTRACE_DETACH, process->tid, 0, 0);
    LOGV("stop tracing %d\n", process->tid);
    longjmp(process->jmpbuf, THREAD_EXIT_CODE_STOP);
}

void syshook_handle_child_signals(syshook_process_t *process, parsed_status_t *parsed_status, status_type_t retsignals)
{
    int rc;

    for (;;) {
        // wait for signal
        syshook_wait_for_signal(process, parsed_status);

        if (parsed_status->type & retsignals)
            return;

        switch (parsed_status->type) {
            case STATUS_TYPE_EXIT:
                LOGD("stopping %d\n", process->tid);

                // stop this tracer thread
                syshook_thread_exit(THREAD_EXIT_CODE_STOP);
                break;

            case STATUS_TYPE_CLONE:
                syshook_handle_new_clone(process->context, process, (pid_t)parsed_status->data);
                syshook_continue(process, 0);
                break;

            case STATUS_TYPE_EXEC_OTHER:
                notify_execve_threads(process->context);
                syshook_thread_exit(THREAD_EXIT_CODE_EXEC_OTHER);
                break;

            case STATUS_TYPE_EXEC:
                LOGV("native execve\n");
                if (!process->expect_execve)
                    LOGF("did not expect execve");

                if (process->context->execve_process) {
                    rc = process->context->execve_process(process);
                    if (rc) {
                        LOGF("error in execve_process\n");
                    }
                }

                process->expect_execve = false;
                syshook_continue(process, 0);
                syshook_thread_exit(THREAD_EXIT_CODE_EXEC);
                break;

            case STATUS_TYPE_SYSCALL:
                if (syshook_handle_child_syscall(process)==0) {
                    syshook_continue(process, 0);
                }
                break;

            case STATUS_TYPE_OTHER:
                if (!process->sigstop_received && parsed_status->signal==SIGSTOP) {
                    LOGD("got first sigstop\n");
                    process->sigstop_received = true;

                    // set options
                    safe_ptrace(PTRACE_SETOPTIONS, process->tid, NULL, (void *)process->context->ptrace_options);

                    // get state
                    syshook_arch_get_state(process, process->state);

                    // set PC
                    syshook_arch_set_pc(process->state, process->handler_context[0]);

                    // apply state
                    syshook_arch_set_state(process, process->state);

                    // continue
                    syshook_continue(process, 0);
                } else {
                    // pass through unknown signals
                    syshook_continue(process, parsed_status->signal);
                }
                break;

            default:
                LOGF("unknown status: %u\n", parsed_status->type);
                break;
        }
    }
}

// public API

syshook_context_t *syshook_create_context(void **sys_call_table)
{
    long ptrace_options = 0;

    // these are needed to get notified of new forks
    ptrace_options |= PTRACE_O_TRACEFORK;
    ptrace_options |= PTRACE_O_TRACEVFORK;
    ptrace_options |= PTRACE_O_TRACECLONE;
    // this allows us to safely identify syscalls
    ptrace_options |= PTRACE_O_TRACESYSGOOD;
    // this notifies us about exec's
    ptrace_options |= PTRACE_O_TRACEEXEC;

    syshook_context_t *context = calloc(1, sizeof(syshook_context_t));
    context->pagesize = getpagesize();
    list_initialize(&context->processes);
    context->sys_call_table = sys_call_table;
    context->ptrace_options = ptrace_options;
    pthread_mutex_init(&context->lock, NULL);
    pthread_cond_init(&context->exit_cond, NULL);
    pthread_mutex_init(&context->exit_mutex, NULL);
    context->archpdata = syshook_arch_init();

    return context;
}

int syshook_execvp(char **argv, void **sys_call_table)
{
    syshook_context_t *context = syshook_create_context(sys_call_table);
    return syshook_execvp_ex(context, argv);
}

int syshook_execvp_ex(syshook_context_t *context, char **argv)
{
    int rc;
    int status;

    if (thread_process) {
        return -1;
    }

    pid_t pid = safe_fork();

    // child
    if (!pid) {
        // start tracing
        safe_ptrace(PTRACE_TRACEME, 0, NULL, NULL);

        // give the parent a chance to set some extra tracing options before we
        // restart the child and let it call exec()
        raise(SIGTRAP);

        // run binary
        execvp(argv[0], argv);

        LOGF("execvp: %s\n", strerror(errno));
    }

    // parent

    context->roottid = pid;

    // Wait for SIGTRAP from the child
    safe_waitpid(pid, &status, __WALL);

    // parse status
    if (WSTOPSIG(status) != SIGTRAP) {
        LOGF("invalid root child status\n");
    }

    // this is needed to prevent the parent exiting while setting up a new clone
    safe_ptrace(PTRACE_SETOPTIONS, pid, NULL, (void *)context->ptrace_options);

    syshook_register_defaults(context);

    // register root process
    syshook_process_t *rootprocess = syshook_handle_new_process(context, pid, pid, -1, -1);
    rootprocess->sigstop_received = true;
    rootprocess->is_root_process = true;

    // run callback
    if (context->create_process) {
        rc = context->create_process(rootprocess);
        if (rc) {
            LOGF("error in create_process\n");
        }
    }

    // run thread loop
    syshook_child_thread(rootprocess);

    // wait for global exit to happen
    while (!context->do_exit) {
        pthread_mutex_lock(&context->exit_mutex);
        pthread_cond_wait(&context->exit_cond, &context->exit_mutex);
        pthread_mutex_unlock(&context->exit_mutex);
    }
    if (context->do_exit!=THREAD_EXIT_CODE_STOP) {
        LOGE("main process exited with error: %d\n", context->do_exit);
    }

    // kill all tracees
    LOGD("root process stopped. killing all tracees\n");
    pthread_mutex_lock(&context->lock);
    if (!list_is_empty(&context->processes)) {
        syshook_process_t *process = list_peek_tail_type(&context->processes, syshook_process_t, node);
        pthread_mutex_lock(&process->lock);

        // this may fail if the process has already exited
        // and the tracee just waits for us to release the context lock
        kill(SIGKILL, process->tid);

        // allow thread to proceed
        // we can't join them because they're detached
        pthread_mutex_unlock(&process->lock);
        pthread_mutex_unlock(&context->lock);

        // re-lock context
        pthread_mutex_lock(&context->lock);
    }
    pthread_mutex_unlock(&context->lock);

    LOGD("ALL CHILDREN FINISHED\n");

    thread_process = NULL;
    return 0;
}

long syshook_invoke_hookee(syshook_process_t *process)
{
    if (!syshook_arch_is_entry(process->state)) {
        LOGF("%s: child is not in entry state\n", __func__);
    }

    // copy new state to process
    syshook_arch_set_state(process, process->state);

    // check if this is execve
    if (syshook_arch_syscall_get(process->state)==SYS_execve)
        process->expect_execve = true;

    // continue
    syshook_continue(process, 0);

    // wait for EXIT
    parsed_status_t parsed_status;
    syshook_handle_child_signals(process, &parsed_status, STATUS_TYPE_SYSCALL);

    // get new state
    syshook_arch_get_state(process, process->state);
    return syshook_arch_result_get(process->state);
}

long syshook_invoke_syscall(syshook_process_t *process, long scno, ...)
{
    int i;
    parsed_status_t parsed_status;
    uint8_t state[syshook_arch_get_state_size()];
    unsigned long instr;
    long pc = syshook_arch_get_pc(process->state);
    bool was_entry = syshook_arch_is_entry(process->state);

    if (syshook_copy_from_user(process, &instr, (void *)pc, sizeof(instr))) {
        LOGF("can't read instruction at PC\n");
    }

    // backup state
    syshook_arch_copy_state(state, process->state);

    // go back to ENTRY
    if (!was_entry) {
        // set back PC
        syshook_arch_set_pc(process->state, pc - syshook_arch_get_instruction_size(process->state, instr));

        // copy new state to process
        syshook_arch_set_state(process, process->state);

        // continue
        syshook_continue(process, 0);

        // wait for ENTRY
        syshook_handle_child_signals(process, &parsed_status, STATUS_TYPE_SYSCALL);

        // get new state
        syshook_arch_get_state(process, process->state);
    }

    // set arguments
    va_list ap;
    va_start(ap, scno);
    for (i=0; i<=6; i++) {
        long arg = va_arg(ap, long);

        syshook_argument_set(process, i, arg);
    }
    va_end(ap);

    // set scno
    syshook_arch_syscall_set(process->state, scno);

    // copy new state to process
    syshook_arch_set_state(process, process->state);

    // check if this is execve
    if (syshook_arch_syscall_get(process->state)==SYS_execve)
        process->expect_execve = true;

    // continue
    syshook_continue(process, 0);

    // wait for EXIT
    syshook_handle_child_signals(process, &parsed_status, STATUS_TYPE_SYSCALL);

    // get new state
    syshook_arch_get_state(process, process->state);

    // get result
    long ret = syshook_arch_result_get(process->state);

    if (was_entry) {
        // set back PC
        syshook_arch_set_pc(process->state, pc - syshook_arch_get_instruction_size(process->state, instr));

        // copy new state to process
        syshook_arch_set_state(process, process->state);

        // continue
        syshook_continue(process, 0);

        // wait for ENTRY
        syshook_handle_child_signals(process, &parsed_status, STATUS_TYPE_SYSCALL);

        // get new state
        syshook_arch_get_state(process, process->state);
    }

    // restore state
    syshook_copy_state_diffs(process->state, state);

    return ret;
}

bool syshook_is_entry(syshook_process_t *process)
{
    return syshook_arch_is_entry(process->state);
}

long syshook_syscall_get(syshook_process_t *process)
{
    return syshook_arch_syscall_get(process->state);
}

void syshook_syscall_set(syshook_process_t *process, long scno)
{
    syshook_arch_syscall_set(process->state, scno);
}

long syshook_result_get(syshook_process_t *process)
{
    return syshook_arch_result_get(process->state);
}

long syshook_argument_get(syshook_process_t *process, int num)
{
    return syshook_arch_argument_get(process->state, num);
}

void syshook_argument_set(syshook_process_t *process, int num, long value)
{
    syshook_arch_argument_set(process->state, num, value);
}

long syshook_copy_from_user(syshook_process_t *process, void *to, const void __user *from, unsigned long n)
{
    errno=0;

    size_t offset=((unsigned long)from)%sizeof(long);
    from-=offset;
    char *dst=(char *)to;
    long buffer=safe_ptrace(PTRACE_PEEKDATA, process->tid, (void *)from, 0);
    if ( buffer==-1 && errno!=0 )
        return 0; // false means failure

    while ( n>0 ) {
        // XXX Theoretically we can make the write faster by writing it whole "long" at a time. This, of course, requires that
        // the alignment be correct on the receiving side as well as the sending side, which isn't trivial.
        // For the time being, this approach is, at least, system call efficient, so we keep it.
        *dst=((const char *)&buffer)[offset];

        offset++;
        dst++;
        n--;

        if ( n>0 && offset==sizeof(long) ) {
            from+=offset;
            offset=0;

            buffer=safe_ptrace(PTRACE_PEEKDATA, process->tid, (void *)from, 0);
            if ( buffer==-1 && errno!=0 )
                return 0; // false means failure
        }
    }

    return errno;
}

long syshook_copy_to_user(syshook_process_t *process, void __user *to, const void *from, unsigned long n)
{
    long buffer;
    size_t offset=((unsigned long)to)%sizeof(long);
    to-=offset; // Make the process PTR aligned

    errno=0;

    if ( offset!=0 ) {
        // We have "Stuff" hanging before the area we need to fill - initialize the buffer
        buffer=safe_ptrace(PTRACE_PEEKDATA, process->tid, to, 0 );
    }

    const char *src=from;

    while ( n>0 && errno==0 ) {
        ((char *)&buffer)[offset]=*src;

        src++;
        offset++;
        n--;

        if ( offset==sizeof(long) ) {
            safe_ptrace(PTRACE_POKEDATA, process->tid, to, (void *)buffer);
            to+=offset;
            offset=0;
        }
    }

    if ( errno==0 && offset!=0 ) {
        // We have leftover data we still need to transfer. Need to make sure we are not
        // overwriting data outside of our intended area
        long buffer2=safe_ptrace(PTRACE_PEEKDATA, process->tid, to, 0 );

        unsigned int i;
        for ( i=offset; i<sizeof(long); ++i )
            ((char *)&buffer)[i]=((char *)&buffer2)[i];

        if ( errno==0 )
            safe_ptrace(PTRACE_POKEDATA, process->tid, to, (void *)buffer);
    }

    return errno;
}

long syshook_strncpy_user(syshook_process_t *process, char *to, const char __user *from, long n)
{
    /* Are we aligned on the "start" front? */
    unsigned int offset=((unsigned long)from)%sizeof(long);
    from-=offset;
    long i=0;
    int done=0;
    int word_offset=0;

    while ( !done ) {
        unsigned long word=safe_ptrace(PTRACE_PEEKDATA, process->tid, (void *)(from+(word_offset++)*sizeof(long)), 0 );

        while ( !done && offset<sizeof(long) && i<n ) {
            to[i]=((char *)&word)[offset]; /* Endianity neutral copy */

            done=to[i]=='\0';
            ++i;
            ++offset;
        }

        offset=0;
        done=done || i>=n;
    }

    return i;
}

char *syshook_strndup_user(syshook_process_t *process, const char __user *s, long n)
{
    char *to = safe_calloc(1, n);
    syshook_strncpy_user(process, to, s, n);
    return to;
}

void *syshook_alloc_user(syshook_process_t *process, size_t size)
{
    return (void *)syshook_invoke_syscall(process, SYS_mmap2, NULL, ROUNDUP(size, process->context->pagesize), PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
}

int syshook_free_user(syshook_process_t *process, void *addr, size_t size)
{
    return (int)syshook_invoke_syscall(process, SYS_munmap, addr, ROUNDUP(size, process->context->pagesize));
}
