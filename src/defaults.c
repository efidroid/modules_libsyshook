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

#include <sys/syscall.h>
#include <linux/sched.h>

#include <common.h>

SYSCALL_DEFINE0(fork)
{
    // Turn the fork/vfork into a clone
    int clone_flags=CLONE_PTRACE|SIGCHLD;

    pid_t pid = (pid_t)syshook_invoke_syscall(process, SYS_clone, clone_flags, 0);

    if(pid!=-1) {
        syshook_process_t* newprocess = syshook_handle_new_process(process->context, pid, pid, process->pid, process->pid);
        newprocess->clone_flags = clone_flags;
    }

    return pid;
}

SYSCALL_DEFINE0(vfork)
{
    if(syshook_is_entry(process)) {
        // Turn the fork/vfork into a clone
        int clone_flags=CLONE_PTRACE|SIGCHLD;
        clone_flags|=CLONE_VFORK|CLONE_VM;

        syshook_syscall_set(process, SYS_clone);
        syshook_argument_set(process, 0, clone_flags);
        syshook_argument_set(process, 1, 0);

        // the process will be continued and we'll get called again, later
        process->handler_context[0] = clone_flags;
        process->exit_handler = sys_vfork;
        process->expect_new_child = true;
        return 0;
    }

    else {
        return syshook_result_get(process);
    }
}

SYSCALL_DEFINE1(clone, unsigned long, clone_flags)
{
    // We do not support containers. If one of the containers related flags was set, fail the call.
    if(clone_flags & (CLONE_NEWIPC|CLONE_NEWNET|CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWUTS)) {
        return -EINVAL;
    }

    // Whatever it originally was, add a CLONE_PTRACE to the flags so that we remain in control
    clone_flags|=CLONE_PTRACE;
    clone_flags&=~CLONE_UNTRACED; // Reset the UNTRACED flag

    // set new clone_flags
    syshook_argument_set(process, 0, (long)clone_flags);
    if(clone_flags & CLONE_VFORK) {
        // the process will be continued and we'll get called again, later
        process->handler_context[0] = clone_flags;
        process->exit_handler = sys_vfork;
        process->expect_new_child = true;
        return 0;
    }

    // call hookee
    pid_t newtid = (pid_t)syshook_invoke_hookee(process);

    if(newtid!=-1) {
        pid_t newpid = newtid;
        pid_t parent = process->pid;

        if(clone_flags&CLONE_THREAD) {
            newpid = process->pid;
        }

        if((clone_flags&CLONE_PARENT) || (clone_flags&CLONE_THREAD)) {
            parent = process->ppid;
        }

        syshook_process_t* newprocess = syshook_handle_new_process(process->context, newpid, newtid, parent, process->pid);
        newprocess->clone_flags = clone_flags;
    }

    return newtid;
}

SYSCALL_DEFINE0(execve)
{
    long rc = syshook_invoke_hookee(process);
    process->expect_execve = true;

    return rc;
}


SYSCALL_DEFINE0(ptrace)
{
    return -1;
}

#define syshook_register_syscall(name) if(!context->sys_call_table[SYS_##name]) context->sys_call_table[SYS_##name] = sys_##name;
void syshook_register_defaults(syshook_context_t* context) {
    // register syscalls
    syshook_register_syscall(fork);
    syshook_register_syscall(vfork);
    syshook_register_syscall(clone);
    syshook_register_syscall(execve);

    syshook_register_syscall(ptrace);
}
