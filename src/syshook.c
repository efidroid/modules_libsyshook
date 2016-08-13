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

#include <common.h>
#include <syshook.h>

static __thread syshook_context_t* thread_context = NULL;

static void syshook_handle_child_signal(syshook_context_t* context, pid_t tid, int status);

static void syshook_continue(syshook_process_t* process, int signal) {
    safe_ptrace(PTRACE_SYSCALL, process->tid, 0, (void*)signal);
}

static syshook_process_t* get_process_data(syshook_context_t* context, pid_t tid) {
    pthread_mutex_lock(&context->lock);
    syshook_process_t *entry;
    list_for_every_entry(&context->processes, entry, syshook_process_t, node) {
        if(entry->tid==tid) {
            pthread_mutex_unlock(&context->lock);
            return entry;
        }
    }
    pthread_mutex_unlock(&context->lock);

    return NULL;
}

syshook_process_t* get_thread_process(void) {
    syshook_context_t* context = syshook_get_thread_context();
    if(!context) return NULL;

    pthread_t self = pthread_self();

    pthread_mutex_lock(&context->lock);
    syshook_process_t *entry;
    list_for_every_entry(&context->processes, entry, syshook_process_t, node) {
        if(entry->thread==self) {
            pthread_mutex_unlock(&context->lock);
            return entry;
        }
    }
    pthread_mutex_unlock(&context->lock);

    return NULL;
}

syshook_context_t* syshook_get_thread_context(void) {
    return thread_context;
}

void syshook_thread_exit(int code) {
    syshook_process_t* process = get_thread_process();
    if(process) {
        longjmp(process->jmpbuf, code);
    }

    safe_exit(code);
}

syshook_process_t* syshook_handle_new_process(syshook_context_t* context, pid_t pid, pid_t tid, pid_t ppid, pid_t cpid) {
    syshook_process_t* process;

    process = safe_calloc(1, sizeof(syshook_process_t));
    process->context = context;
    process->pid = pid;
    process->tid = tid;
    process->ppid = ppid;
    process->creatorpid = cpid;
    process->original_state = safe_calloc(1, PLATFORM_STATE_SIZE);
    process->state = safe_calloc(1, PLATFORM_STATE_SIZE);
    process->sigstop_received = false;
    pthread_mutex_init(&process->lock, NULL);
    pthread_cond_init(&process->cond, NULL);

    pthread_mutex_lock(&context->lock);
    list_add_tail(&context->processes, &process->node);
    pthread_mutex_unlock(&context->lock);

    LOGD("new process pid=%d tid=%d ppid=%d cpid=%d\n", pid, tid, ppid, cpid);

    return process;
}

static void syshook_handle_stop_process(syshook_process_t* process) {
    if(!process)
        return;

    LOGD("stopping %d\n", process->tid);
    pthread_mutex_lock(&process->lock);
    process->stopped = true;
    pthread_mutex_unlock(&process->lock);
}

void syshook_delete_process(syshook_process_t* process) {
    LOGD("stopped %d\n", process->tid);

    pthread_mutex_lock(&process->context->lock);
    list_delete(&process->node);
    pthread_mutex_unlock(&process->context->lock);

    free(process->state);
    free(process->original_state);
    free(process);
}

static long syshook_invoke_syscall_handler(syshook_process_t* process, long scno, ...) {
    long (*fn)(syshook_process_t*, ...);

    if(process->exit_handler) {
        fn = process->exit_handler;
        process->exit_handler = NULL;
    }

    else {
        if(scno>=SYSHOOK_NUM_SYSCALLS || !process->context->sys_call_table[scno])
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

static void syshook_copy_state_diffs(void* dst, void* src) {
    // restore arguments
    int i;
    for(i=0; i<=6; i++) {
        long val = syshook_arch_argument_get(dst, i);
        long val_backup = syshook_arch_argument_get(src, i);
        if(val!=val_backup) {
            syshook_arch_argument_set(dst, i, val_backup);
        }
    }

    // restore scno
    int scno_now = syshook_arch_syscall_get(dst);
    int scno_backup = syshook_arch_syscall_get(src);
    if(scno_now!=scno_backup) {
        syshook_arch_syscall_set(dst, scno_backup);
    }

    // restore result
    int rc_now = syshook_arch_result_get(dst);
    int rc_backup = syshook_arch_result_get(src);
    if(rc_now!=rc_backup) {
        syshook_arch_result_set(dst, rc_backup);
    }
}

static int syshook_handle_child_syscall(syshook_process_t* process) {
    // get current state
    syshook_arch_get_state(process, process->original_state);

    // copy state so we can modify it and still have a copy
    syshook_arch_copy_state(process->state, process->original_state);

    int scno = syshook_arch_syscall_get(process->state);
    bool is_entry = syshook_arch_is_entry(process->state);

    // ignore this one and just continue
    if(process->expect_execve && scno==SYS_execve) {
        process->expect_execve = false;
        return 0;
    }

    // this call will not have an exit, continue
    if(scno==SYS_restart_syscall) {
        return 0;
    }

    // the syscall had no handler and got ignored
    if(process->expect_syscall_exit) {
        process->expect_syscall_exit = false;
        return 0;
    }

    //LOGD("[%d:%d][SYSCALL][%s] %d\n", process->pid, process->tid, is_entry?"ENTRY":"EXIT", scno);

    if(!is_entry && !process->exit_handler) {
        LOGE("received exit but no exit handler is set\n");
        safe_exit(1);
    }

    // apparently, the exit did not happen
    if(is_entry) {
        process->expect_syscall_exit = false;
    }

    long ret = -1;
    bool handler_exists = (scno<SYSHOOK_NUM_SYSCALLS && process->context->sys_call_table[scno]) || process->exit_handler;
    if(handler_exists) {
        ret = syshook_invoke_syscall_handler(process, scno);

        // call handler again later if/when the syscall returns
        if(process->exit_handler) {
            if(!syshook_arch_is_entry(process->state)) {
                LOGE("exit_handler is set, but process is in exit state already");
                safe_exit(1);
            }

            // copy new state to process
            syshook_arch_set_state(process, process->state);
            return 0;
        }

        // the handler didn't call the original function, so convert the call to getpid
        is_entry = syshook_arch_is_entry(process->state);
        if(is_entry) {
            syshook_arch_syscall_set(process->state, SYS_getpid);
        }
    }

    else {
        // ignore this call
        process->expect_syscall_exit = true;
        return 0;
    }

    // make sure we leave this function with the child in EXIT
    is_entry = syshook_arch_is_entry(process->state);
    if(is_entry) {
        int status;

        // copy new state to process
        syshook_arch_set_state(process, process->state);

        // continue
        syshook_continue(process, 0);

        // wait for EXIT
        safe_waitpid(process->tid, &status, __WALL);

        // parse status
        parsed_status_t parsed_status;
        syshook_parse_child_signal(process->tid, status, &parsed_status);

        // verify status
        switch(parsed_status.type) {
            case STATUS_TYPE_SYSCALL:
                // get new state
                syshook_arch_get_state(process, process->state);

                // this should always be getpid, so keep the original return value
                syshook_arch_result_get(process->state);
                break;
            case STATUS_TYPE_EXIT:
                syshook_handle_stop_process(process);
                return -1;

            default:
                LOGE("invalid child status during syscall: %d\n", parsed_status.type);
                safe_exit(1);
        }
    }

    // restore state
    syshook_copy_state_diffs(process->state, process->original_state);

    // set return value
    // this makes sure that set_state uses the result cache instead of the r0 register value
    syshook_arch_result_set(process->state, ret);

    // copy new state to process
    syshook_arch_set_state(process, process->state);

    process->exit_handler = NULL;

    return 0;
}

void syshook_parse_child_signal(pid_t tid, int status, parsed_status_t* pstatus) {
    int signal = 0;

    if(WIFEXITED(status)) {
        signal = WEXITSTATUS(status);
        LOGD("[%d] exit with %d\n", tid, signal);
        pstatus->type = STATUS_TYPE_EXIT;
    }

    else if(WIFSIGNALED(status)) {
        signal = WTERMSIG(status);
        LOGD("[%d] received %s\n", tid, sig2str(signal));
        pstatus->type = STATUS_TYPE_EXIT;
    }

    else if(WIFSTOPPED(status)) {
        signal = WSTOPSIG(status);

        if(signal == SIGTRAP) {
            siginfo_t siginfo;
            unsigned long data;

            safe_ptrace(PTRACE_GETSIGINFO, tid, NULL, &siginfo);
            safe_ptrace(PTRACE_GETEVENTMSG, tid, NULL, &data);
            
            int event = siginfo.si_code>>8;
            switch(event) {
                case PTRACE_EVENT_VFORK:
                case PTRACE_EVENT_FORK:
                case PTRACE_EVENT_CLONE:
                    LOGD("[%d][TRAP] event=%s clone_pid=%d\n", tid, ptraceevent2str(event), (pid_t)data);
                    pstatus->type = STATUS_TYPE_CLONE;
                    break;

                case PTRACE_EVENT_SECCOMP:
                    LOGD("[%d][TRAP] event=%s seccomp\n", tid, ptraceevent2str(event));
                    pstatus->type = STATUS_TYPE_OTHER;
                    break;

                case 0:
                    pstatus->type = STATUS_TYPE_SYSCALL;
                    break;

                default:
                    LOGE("[%d][TRAP] unknown event %d\n", tid, event);
                    safe_exit(1);
            }

            // suppress signal
            signal = 0;

            pstatus->siginfo = siginfo;
            pstatus->data = data;
            pstatus->ptrace_event = event;
        }

        else {
            LOGD("[%d] stopped with %s\n", tid, sig2str(signal));
            pstatus->type = STATUS_TYPE_OTHER;
        }
    }

    else if(WIFCONTINUED(status)) {
        LOGD("[%d] continued\n", tid);
        pstatus->type = STATUS_TYPE_OTHER;
    }

    else {
        LOGE("[%d] unknown status 0x%x\n", tid, status);
        safe_exit(1);
    }

    pstatus->signal = signal;
}

static void* syshook_child_thread(void* pdata) {
    syshook_process_t* process = pdata;
    int status;

    thread_context = process->context;

    int rc = setjmp(process->jmpbuf);
    if(rc) {
        goto stopthread;
    }

    // attach to process
    safe_ptrace(PTRACE_ATTACH, process->tid, 0, (void*)0);

    // main loop
    while(!process->stopped) {
        // wait for change
        pid_t tid = safe_waitpid(process->tid, &status, __WALL);

        syshook_handle_child_signal(process->context, tid, status);
    }

stopthread:
    syshook_delete_process(process);

    return NULL;
}

static void syshook_handle_new_clone(syshook_context_t* context, syshook_process_t* creator, pid_t clone_tid) {
    int status;
    parsed_status_t parsed_status;

    // register process
    long clone_flags = creator->handler_context[2];
    pid_t clone_pid = clone_tid;
    pid_t clone_ppid = creator->pid;

    if(clone_flags&CLONE_THREAD) {
        clone_pid = creator->pid;
    }

    if((clone_flags&CLONE_PARENT) || (clone_flags&CLONE_THREAD)) {
        clone_ppid = creator->ppid;
    }

    syshook_process_t* process = syshook_handle_new_process(context, clone_pid, clone_tid, clone_ppid, creator->tid);
    process->clone_flags = clone_flags;

    // wait for SIGSTOP
    safe_waitpid(process->tid, &status, __WALL);
    syshook_parse_child_signal(clone_tid, status, &parsed_status);
    if(!(parsed_status.type==STATUS_TYPE_OTHER && parsed_status.signal==SIGSTOP)) {
        syshook_thread_exit(1);
    }

    // get state
    syshook_arch_get_state(process, process->state);

    // set PC
    process->handler_context[0] = syshook_arch_get_pc(process->state);
    syshook_arch_set_pc(process->state, creator->handler_context[0]);

    // apply state
    syshook_arch_set_state(process, process->state);

    // detach
    safe_ptrace(PTRACE_DETACH, process->tid, 0, 0);

    // start thread
    pthread_create(&(process->thread), NULL, syshook_child_thread, process);
}

static void syshook_handle_child_signal(syshook_context_t* context, pid_t tid, int status) {
    parsed_status_t parsed_status;

    syshook_process_t* process = get_process_data(context, tid);

    syshook_parse_child_signal(tid, status, &parsed_status);
    switch(parsed_status.type) {
        case STATUS_TYPE_EXIT:
            syshook_handle_stop_process(process);
            break;

        case STATUS_TYPE_CLONE:
            syshook_handle_new_clone(context, process, (pid_t)parsed_status.data);
            syshook_continue(process, 0);
            break;

        case STATUS_TYPE_SYSCALL:
            if(!process) {
                LOGE("received syscall from unknown child\n");
                safe_exit(1);
            }

            if(syshook_handle_child_syscall(process)==0) {
                syshook_continue(process, 0);
            }
            break;
            
        case STATUS_TYPE_OTHER:
            if(!process) {
                LOGE("received signal from unknown child\n");
                safe_exit(1);
            }

            if(!process->sigstop_received && parsed_status.signal==SIGSTOP) {
                LOGD("got first sigstop\n");
                process->sigstop_received = true;

                // set options
                safe_ptrace(PTRACE_SETOPTIONS, process->tid, NULL, (void*)context->ptrace_options);

                // get state
                syshook_arch_get_state(process, process->state);

                // set PC
                syshook_arch_set_pc(process->state, process->handler_context[0]);

                // apply state
                syshook_arch_set_state(process, process->state);

                // continue
                syshook_continue(process, 0);
            }
            else {
                // pass through unknown signals
                syshook_continue(process, parsed_status.signal);
            }
            break;

        default:
            LOGE("unknown status: %u\n", parsed_status.type);
            safe_exit(1);
            break;
    }
}

// public API

int syshook_execvp(char **argv, void** sys_call_table) {
    int status;

    if(thread_context) {
        return -1;
    }

    pid_t pid = safe_fork();

    // child
    if(!pid) {
        // start tracing
        safe_ptrace(PTRACE_TRACEME, 0, NULL, NULL);

        // Give the parent to chance to set some extra tracing options before we
        // restart the child and let it call exec()
        raise(SIGTRAP);

        // run binary
        execvp(argv[0], argv);

        perror("execvp");
        safe_exit(1);
    }

    // parent

    // Wait for SIGTRAP from the child
    safe_waitpid(pid, &status, __WALL);

    // parse status
    if (WSTOPSIG(status) != SIGTRAP) {
        LOGE("invalid status2\n");
        safe_exit(1);
    }

    // set ptrace options
    long ptrace_options = 0;

    // these are needed to get notified of new forks
    ptrace_options |= PTRACE_O_TRACEFORK;
    ptrace_options |= PTRACE_O_TRACEVFORK;
    ptrace_options |= PTRACE_O_TRACECLONE;

    // this is needed to prevent the parent exiting while setting up a new clone
    safe_ptrace(PTRACE_SETOPTIONS, pid, NULL, (void*)ptrace_options);

    // init context data
    syshook_context_t* context = safe_calloc(1, sizeof(syshook_context_t));
    context->pagesize = getpagesize();
    list_initialize(&context->processes);
    context->sys_call_table = sys_call_table;
    context->ptrace_options = ptrace_options;
    pthread_mutex_init(&context->lock, NULL);
    thread_context = context;

    syshook_register_defaults(context);

    // register root process
    syshook_process_t* rootprocess = syshook_handle_new_process(context, pid, pid, -1, -1);
    rootprocess->sigstop_received = true;

    // continue child
    syshook_continue(rootprocess, 0);

    // main loop
    while(!rootprocess->stopped) {
        // wait for change
        pid_t tid = safe_waitpid(pid, &status, __WALL);

        syshook_handle_child_signal(context, tid, status);
    }
    syshook_delete_process(rootprocess);

    LOGD("root process stopped. killing all tracees\n");

    // kill all tracees
    pthread_mutex_lock(&context->lock);
    while(!list_is_empty(&context->processes)) {
        syshook_process_t* process = list_peek_tail_type(&context->processes, syshook_process_t, node);

        pthread_mutex_lock(&process->lock);
        if(!process->stopped) {
            kill(SIGKILL, process->tid);

            pthread_mutex_unlock(&process->lock);
            pthread_mutex_unlock(&context->lock);
            pthread_join(process->thread, NULL);

            pthread_mutex_lock(&context->lock);
        } else {
            pthread_mutex_unlock(&process->lock);
        }
    }
    pthread_mutex_unlock(&context->lock);

    LOGD("ALL CHILDREN FINISHED\n");

    thread_context = NULL;
    return 0;
}

long syshook_invoke_hookee(syshook_process_t* process) {
    int status;

    if(!syshook_arch_is_entry(process->state)) {
        LOGE("%s: child is not in entry state\n", __func__);
        safe_exit(1);
    }

    // copy new state to process
    syshook_arch_set_state(process, process->state);

    // continue
    syshook_continue(process, 0);

    // wait for EXIT
    safe_waitpid(process->tid, &status, __WALL);

    // parse status
    parsed_status_t parsed_status;
    syshook_parse_child_signal(process->tid, status, &parsed_status);

    // verify status
    switch(parsed_status.type) {
        case STATUS_TYPE_EXIT:
            syshook_handle_stop_process(process);
            return 0;

        case STATUS_TYPE_SYSCALL:
            // get new state
            syshook_arch_get_state(process, process->state);
            return syshook_arch_result_get(process->state);

        default:
            LOGE("%s: invalid status: %d\n", __func__, parsed_status.type);
            safe_exit(1);
    }
}

long syshook_invoke_syscall(syshook_process_t* process, long scno, ...) {
    int status;
    int i;
    parsed_status_t parsed_status;
    uint8_t* state[PLATFORM_STATE_SIZE];
    unsigned long instr;
    long pc = syshook_arch_get_pc(process->state);
    bool was_entry = syshook_arch_is_entry(process->state);

    if(syshook_copy_from_user(process, &instr, (void*)pc, sizeof(instr))) {
        LOGE("can't read instruction at PC\n");
        safe_exit(1);
    }

    // backup state
    syshook_arch_copy_state(state, process->state);

    // go back to ENTRY
    if(!was_entry) {
        // set back PC
        syshook_arch_set_pc(process->state, pc - syshook_arch_get_instruction_size(instr));

        // copy new state to process
        syshook_arch_set_state(process, process->state);

        // continue
        syshook_continue(process, 0);

        // wait for ENTRY
        safe_waitpid(process->tid, &status, __WALL);

        // parse status
        syshook_parse_child_signal(process->tid, status, &parsed_status);

        // verify status
        switch(parsed_status.type) {
            case STATUS_TYPE_SYSCALL:
                // get new state
                syshook_arch_get_state(process, process->state);
                break;

            default:
                LOGE("%s: invalid status: %d\n", __func__, parsed_status.type);
                safe_exit(1);
        }
    }

    // set arguments
    va_list ap;
    va_start(ap, scno);
    for(i=0; i<=6; i++) {
        long arg = va_arg(ap, long);

        syshook_argument_set(process, i, arg);
    }
    va_end(ap);

    // set scno
    syshook_arch_syscall_set(process->state, scno);

    // copy new state to process
    syshook_arch_set_state(process, process->state);

    // continue
    syshook_continue(process, 0);

    // wait for EXIT
    safe_waitpid(process->tid, &status, __WALL);

    // parse status
    syshook_parse_child_signal(process->tid, status, &parsed_status);

    // verify status
    switch(parsed_status.type) {
        case STATUS_TYPE_EXIT:
            syshook_handle_stop_process(process);
            return 0;

        case STATUS_TYPE_SYSCALL:
            // get new state
            syshook_arch_get_state(process, process->state);
            break;

        default:
            LOGE("%s: invalid status: %d\n", __func__, parsed_status.type);
            safe_exit(1);
    }

    // get result
    long ret = syshook_arch_result_get(process->state);

    if(was_entry) {
        // set back PC
        syshook_arch_set_pc(process->state, pc - syshook_arch_get_instruction_size(instr));

        // copy new state to process
        syshook_arch_set_state(process, process->state);

        // continue
        syshook_continue(process, 0);

        // wait for ENTRY
        safe_waitpid(process->tid, &status, __WALL);

        // parse status
        syshook_parse_child_signal(process->tid, status, &parsed_status);

        // verify status
        switch(parsed_status.type) {
            case STATUS_TYPE_SYSCALL:
                // get new state
                syshook_arch_get_state(process, process->state);
                break;

            default:
            LOGE("%s: invalid status: %d\n", __func__, parsed_status.type);
            safe_exit(1);
        }
    }

    // restore state
    syshook_copy_state_diffs(process->state, state);

    return ret;
}

bool syshook_is_entry(syshook_process_t* process) {
    return syshook_arch_is_entry(process->state);
}

void syshook_syscall_set(syshook_process_t* process, int scno) {
    syshook_arch_syscall_set(process->state, scno);
}

long syshook_result_get(syshook_process_t* process) {
    return syshook_arch_result_get(process->state);
}

long syshook_argument_get(syshook_process_t* process, int num) {
    return syshook_arch_argument_get(process->state, num);
}

void syshook_argument_set(syshook_process_t* process, int num, long value) {
    syshook_arch_argument_set(process->state, num, value);
}

long syshook_copy_from_user(syshook_process_t* process, void *to, const void __user * from, unsigned long n) {
    errno=0;

    size_t offset=((unsigned long)from)%sizeof(long);
    from-=offset;
    char *dst=(char *)to;
    long buffer=safe_ptrace(PTRACE_PEEKDATA, process->tid, (void*)from, 0);
    if( buffer==-1 && errno!=0 )
        return 0; // false means failure

    while( n>0 ) {
        // XXX Theoretically we can make the write faster by writing it whole "long" at a time. This, of course, requires that
        // the alignment be correct on the receiving side as well as the sending side, which isn't trivial.
        // For the time being, this approach is, at least, system call efficient, so we keep it.
        *dst=((const char *)&buffer)[offset];

        offset++;
        dst++;
        n--;

        if( n>0 && offset==sizeof(long) ) {
            from+=offset;
            offset=0;

            buffer=safe_ptrace(PTRACE_PEEKDATA, process->tid, (void*)from, 0);
            if( buffer==-1 && errno!=0 )
                return 0; // false means failure
        }
    }

    return errno;
}

long syshook_copy_to_user(syshook_process_t* process, void __user *to, const void *from, unsigned long n)
{
    long buffer;
    size_t offset=((unsigned long)to)%sizeof(long);
    to-=offset; // Make the process PTR aligned

    errno=0;

    if( offset!=0 ) {
        // We have "Stuff" hanging before the area we need to fill - initialize the buffer
        buffer=safe_ptrace(PTRACE_PEEKDATA, process->tid, to, 0 );
    }

    const char *src=from;

    while( n>0 && errno==0 ) {
        ((char *)&buffer)[offset]=*src;

        src++;
        offset++;
        n--;

        if( offset==sizeof(long) ) {
            safe_ptrace(PTRACE_POKEDATA, process->tid, to, (void*)buffer);
            to+=offset;
            offset=0;
        }
    }

    if( errno==0 && offset!=0 ) {
        // We have leftover data we still need to transfer. Need to make sure we are not
        // overwriting data outside of our intended area
        long buffer2=safe_ptrace(PTRACE_PEEKDATA, process->tid, to, 0 );

        unsigned int i;
        for( i=offset; i<sizeof(long); ++i )
            ((char *)&buffer)[i]=((char *)&buffer2)[i];

        if( errno==0 )
            safe_ptrace(PTRACE_POKEDATA, process->tid, to, (void*)buffer);
    }

    return errno;
}

long syshook_strncpy_user(syshook_process_t* process, char *to, const char __user *from, long n) {
    /* Are we aligned on the "start" front? */
    unsigned int offset=((unsigned long)from)%sizeof(long);
    from-=offset;
    long i=0;
    int done=0;
    int word_offset=0;

    while( !done ) {
        unsigned long word=safe_ptrace(PTRACE_PEEKDATA, process->tid, (void*)(from+(word_offset++)*sizeof(long)), 0 );

        while( !done && offset<sizeof(long) && i<n ) {
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

char* syshook_strndup_user(syshook_process_t* process, const char __user *s, long n) {
    char* to = safe_calloc(1, n);
    syshook_strncpy_user(process, to, s, n);
    return to;
} 
