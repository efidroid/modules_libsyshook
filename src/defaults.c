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

static long handle_fork(syshook_process_t *process, unsigned long clone_flags);

SYSCALL_DEFINE0(fork)
{
    return handle_fork(process, 0);
}

SYSCALL_DEFINE0(vfork)
{
    return handle_fork(process, 0);
}

SYSCALL_DEFINE1(clone, unsigned long, clone_flags)
{
    return handle_fork(process, clone_flags);
}

static long handle_fork(syshook_process_t *process, unsigned long clone_flags)
{
    if (syshook_is_entry(process)) {
        // setup process trap
        syshook_arch_setup_process_trap(process);

        // store context data
        process->handler_context[2] = clone_flags;

        // set ourself as exit handler
        process->exit_handler = sys_clone;
        return 0;
    } else {
        return syshook_result_get(process);
    }
}

SYSCALL_DEFINE0(ptrace)
{
    return -1;
}

#define syshook_register_syscall(name) if(!context->sys_call_table[SYS_##name]) context->sys_call_table[SYS_##name] = sys_##name;
void syshook_register_defaults(syshook_context_t *context)
{
    // register syscalls
    syshook_register_syscall(fork);
    syshook_register_syscall(vfork);
    syshook_register_syscall(clone);

    syshook_register_syscall(ptrace);
}
