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

#include <common.h>
#include <syshook.h>

static void syshook_handle_child_signal(syshook_context_t* context, pid_t pid, int status);

static void syshook_continue(syshook_process_t* process, int signal) {
    safe_ptrace(PTRACE_SYSCALL, process->pid, 0, (void*)signal);
}

static syshook_process_t* get_process_data(syshook_context_t* context, pid_t pid) {
    syshook_process_t *entry;
    list_for_every_entry(&context->processes, entry, syshook_process_t, node) {
        if(entry->pid==pid)
            return entry;
    }

    return NULL;
}

syshook_process_t* syshook_handle_new_process(syshook_context_t* context, pid_t ppid, pid_t pid) {
    syshook_process_t* process = safe_calloc(1, sizeof(syshook_process_t));
    process->context = context;
    process->pid = pid;
    process->ppid = ppid;
    process->creatorpid = process->ppid;
    process->original_state = safe_calloc(1, PLATFORM_STATE_SIZE);
    process->state = safe_calloc(1, PLATFORM_STATE_SIZE);
    process->sigstop_received = false;

    if(ppid==-1)
        process->sigstop_received = true;

    list_add_tail(&context->processes, &process->node);

    LOGD("new process pid=%d ppid=%d\n", pid, ppid);

    return process;
}

static void syshook_handle_stop_process(syshook_process_t* process) {
    if(!process)
        return;

    LOGD("stopping %d\n", process->pid);

    list_delete(&process->node);

    free(process->state);
    free(process->original_state);
    free(process);
}

static long syshook_invoke_syscall_handler(syshook_process_t* process, long scno, ...) {
    if(scno>=SYSHOOK_NUM_SYSCALLS || !process->context->sys_call_table[scno])
        return -1;

    long (*fn)(syshook_process_t*, ...) = process->context->sys_call_table[scno];
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
    // restore all arguments but result
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

    //LOGD("[%d][SYSCALL][%s] %d\n", process->pid, is_entry?"ENTRY":"EXIT", scno);

    if(!is_entry) {
        LOGE("invalid status\n");
        safe_exit(-1);
    }

    long ret = -1;
    bool handler_exists = (scno<SYSHOOK_NUM_SYSCALLS && process->context->sys_call_table[scno]);
    if(handler_exists) {
        ret = syshook_invoke_syscall_handler(process, scno);

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
        safe_waitpid(process->pid, &status, __WALL);

        // parse status
        parsed_status_t parsed_status;
        syshook_parse_child_signal(process, status, &parsed_status);

        // verify status
        switch(parsed_status.type) {
            case STATUS_TYPE_SYSCALL:
                // get new state
                syshook_arch_get_state(process, process->state);

                ret = syshook_arch_result_get(process->state);
                break;
            case STATUS_TYPE_EXIT:
                syshook_handle_stop_process(process);
                return -1;

            default:
                LOGE("invalid status\n");
                safe_exit(-1);
        }
    }

    // restore state
    syshook_copy_state_diffs(process->state, process->original_state);

    // set return value
    // this makes sure that set_state uses the result cache instead of thr r0 register value
    syshook_arch_result_set(process->state, ret);

    // copy new state to process
    syshook_arch_set_state(process, process->state);

    return 0;
}

void syshook_parse_child_signal(syshook_process_t* process, int status, parsed_status_t* pstatus) {
    int signal = 0;

    if(WIFEXITED(status)) {
        signal = WEXITSTATUS(status);
        LOGD("[%d] exit with %d\n", process->pid, signal);
        pstatus->type = STATUS_TYPE_EXIT;
    }

    else if(WIFSIGNALED(status)) {
        signal = WTERMSIG(status);
        LOGD("[%d] received %s\n", process->pid, sig2str(signal));
        pstatus->type = STATUS_TYPE_EXIT;
    }

    else if(WIFSTOPPED(status)) {
        signal = WSTOPSIG(status);

        if(signal==SIGTRAP) {
            siginfo_t siginfo;
            unsigned long data;

            safe_ptrace(PTRACE_GETSIGINFO, process->pid, NULL, &siginfo);
            safe_ptrace(PTRACE_GETEVENTMSG, process->pid, NULL, &data);
            
            int event = siginfo.si_code>>8;
            switch(event) {
                case PTRACE_EVENT_EXIT:
                    LOGD("[%d][TRAP] event=%s exit_status=%d\n", process->pid, ptraceevent2str(event), (int)data);
                    pstatus->type = STATUS_TYPE_EXIT;
                    break;

                case PTRACE_EVENT_VFORK:
                case PTRACE_EVENT_FORK:
                case PTRACE_EVENT_CLONE:
                case PTRACE_EVENT_VFORK_DONE:
                    LOGD("[%d][TRAP] event=%s clone_pid=%d\n", process->pid, ptraceevent2str(event), (pid_t)data);
                    pstatus->type = STATUS_TYPE_CLONE;
                    break;

                case PTRACE_EVENT_SECCOMP:
                    LOGD("[%d][TRAP] event=%s seccomp\n", process->pid, ptraceevent2str(event));
                    pstatus->type = STATUS_TYPE_OTHER;
                    break;

                case 0:
                    pstatus->type = STATUS_TYPE_SYSCALL;
                    break;

                default:
                    LOGE("[%d][TRAP] unknown event %d\n", process->pid, event);
                    safe_exit(-1);
            }

            // suppress signal
            signal = 0;

            pstatus->siginfo = siginfo;
            pstatus->data = data;
            pstatus->ptrace_event = event;
        }

        else {
            LOGD("[%d] stopped with %s\n", process->pid, sig2str(signal));
            pstatus->type = STATUS_TYPE_OTHER;
        }
    }

    else if(WIFCONTINUED(status)) {
        LOGD("[%d] continued\n", process->pid);
        pstatus->type = STATUS_TYPE_OTHER;
    }

    else {
        LOGE("[%d] unknown status 0x%x\n", process->pid, status);
        safe_exit(-1);
    }

    pstatus->signal = signal;
}

static void syshook_handle_child_signal(syshook_context_t* context, pid_t pid, int status) {
    parsed_status_t parsed_status;

    syshook_process_t* process = get_process_data(context, pid);
    syshook_parse_child_signal(process, status, &parsed_status);

    switch(parsed_status.type) {
        case STATUS_TYPE_EXIT:
            syshook_handle_stop_process(process);
            break;

        case STATUS_TYPE_CLONE:
            // TODO
            syshook_continue(process, 0);
            break;

        case STATUS_TYPE_SYSCALL:
            if(syshook_handle_child_syscall(process)==0) {
                syshook_continue(process, 0);
            }
            break;
            
        case STATUS_TYPE_OTHER:
            if(!process->sigstop_received && parsed_status.signal==SIGSTOP) {
                LOGD("got first sigstop\n");
                process->sigstop_received = true;
                syshook_continue(process, 0);
            }
            else {
                syshook_continue(process, parsed_status.signal);
            }
            break;
    }
}

// public API

int syshook_execve(char **argv, void** sys_call_table) {
    int status;
    pid_t pid = safe_fork();

    // child
    if(!pid) {
        // start tracing
        safe_ptrace(PTRACE_TRACEME, 0, NULL, NULL);

        // run binary
        execvp(argv[0], argv);

        perror("execvp");
        safe_exit(-1);
    }

    // parent

    // init context data
    syshook_context_t* context = safe_calloc(1, sizeof(syshook_context_t));
    context->pagesize = getpagesize();
    list_initialize(&context->processes);
    context->sys_call_table = sys_call_table;

    syshook_register_defaults(context);

    // register root process
    syshook_handle_new_process(context, -1, pid);

    // main loop
    while(!list_is_empty(&context->processes)) {
        // wait for change
        pid = safe_waitpid(-1, &status, __WALL);

        syshook_handle_child_signal(context, pid, status);
    }

    LOGD("ALL CHILDS FINISHED\n");

    return 0;
}

long syshook_invoke_hookee(syshook_process_t* process) {
    int status;

    if(!syshook_arch_is_entry(process->state)) {
        LOGE("invalid state\n");
        safe_exit(-1);
    }

    // copy new state to process
    syshook_arch_set_state(process, process->state);

    // continue
    syshook_continue(process, 0);

    // wait for EXIT
    safe_waitpid(process->pid, &status, __WALL);

    // parse status
    parsed_status_t parsed_status;
    syshook_parse_child_signal(process, status, &parsed_status);

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
            LOGE("invalid status\n");
            safe_exit(-1);
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
        safe_exit(-1);
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
        safe_waitpid(process->pid, &status, __WALL);

        // parse status
        syshook_parse_child_signal(process, status, &parsed_status);

        // verify status
        switch(parsed_status.type) {
            case STATUS_TYPE_SYSCALL:
                // get new state
                syshook_arch_get_state(process, process->state);
                break;

            default:
                LOGE("invalid status\n");
                safe_exit(-1);
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
    safe_waitpid(process->pid, &status, __WALL);

    // parse status
    syshook_parse_child_signal(process, status, &parsed_status);

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
            LOGE("invalid status\n");
            safe_exit(-1);
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
        safe_waitpid(process->pid, &status, __WALL);

        // parse status
        syshook_parse_child_signal(process, status, &parsed_status);

        // verify status
        switch(parsed_status.type) {
            case STATUS_TYPE_SYSCALL:
                // get new state
                syshook_arch_get_state(process, process->state);
                break;

            default:
                LOGE("invalid status\n");
                safe_exit(-1);
        }
    }

    // restore state
    syshook_copy_state_diffs(process->state, state);

    return ret;
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
    long buffer=safe_ptrace(PTRACE_PEEKDATA, process->pid, (void*)from, 0);
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

            buffer=safe_ptrace(PTRACE_PEEKDATA, process->pid, (void*)from, 0);
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
        buffer=safe_ptrace(PTRACE_PEEKDATA, process->pid, to, 0 );
    }

    const char *src=from;

    while( n>0 && errno==0 ) {
        ((char *)&buffer)[offset]=*src;

        src++;
        offset++;
        n--;

        if( offset==sizeof(long) ) {
            safe_ptrace(PTRACE_POKEDATA, process->pid, to, (void*)buffer);
            to+=offset;
            offset=0;
        }
    }

    if( errno==0 && offset!=0 ) {
        // We have leftover data we still need to transfer. Need to make sure we are not
        // overwriting data outside of our intended area
        long buffer2=safe_ptrace(PTRACE_PEEKDATA, process->pid, to, 0 );

        unsigned int i;
        for( i=offset; i<sizeof(long); ++i )
            ((char *)&buffer)[i]=((char *)&buffer2)[i];

        if( errno==0 )
            safe_ptrace(PTRACE_POKEDATA, process->pid, to, (void*)buffer);
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
        unsigned long word=safe_ptrace(PTRACE_PEEKDATA, process->pid, (void*)(from+(word_offset++)*sizeof(long)), 0 );

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
