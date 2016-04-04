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

long do_fork(syshook_process_t* process, bool is_vfork) {
    // Turn the fork/vfork into a clone
    int clone_flags=CLONE_PTRACE|SIGCHLD;

    if(is_vfork) {
        clone_flags|=CLONE_VFORK|CLONE_VM;
    }

    long rc = syshook_invoke_syscall(process, SYS_clone, clone_flags, 0);

    if(rc!=-1) {
        syshook_process_t* newprocess = syshook_handle_new_process(process->context, process->pid, (pid_t)rc);
        newprocess->clone_flags = clone_flags;
    }

    return rc;
}

SYSCALL_DEFINE0(fork)
{
    return do_fork(process, false);
}

SYSCALL_DEFINE0(vfork)
{
    return do_fork(process, true);
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

    // call hookee
    syshook_argument_set(process, 0, (long)clone_flags);
    pid_t newpid = (pid_t)syshook_invoke_hookee(process);

    if(newpid!=-1) {
        pid_t parent = process->pid;

        if((clone_flags&CLONE_PARENT) || (clone_flags&CLONE_THREAD))
            parent = process->ppid;

        syshook_process_t* newprocess = syshook_handle_new_process(process->context, parent, newpid);
        newprocess->clone_flags = clone_flags;
    }

    return newpid;
}

SYSCALL_DEFINE0(execve)
{
    long rc = syshook_invoke_hookee(process);
    process->expect_execve = true;

    return rc;
}

#define syshook_register_syscall(name) if(!context->sys_call_table[SYS_##name]) context->sys_call_table[SYS_##name] = sys_##name;
void syshook_register_defaults(syshook_context_t* context) {
    // register syscalls
    syshook_register_syscall(fork);
    syshook_register_syscall(vfork);
    syshook_register_syscall(clone);
    syshook_register_syscall(execve);
}
