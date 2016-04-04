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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <signal.h>
#include <syshook.h>

#include <linux/sched.h>
#include <errno.h>

syshook_process_t* syshook_handle_new_process(syshook_context_t* context, pid_t ppid, pid_t pid);

static void* sys_call_table[SYSHOOK_NUM_SYSCALLS] = {0};

SYSCALL_DEFINE0(fork)
{
    printf("%s\n", __func__);
    return syshook_invoke_hookee(process);
}

SYSCALL_DEFINE0(vfork)
{
    printf("%s\n", __func__);
    return syshook_invoke_hookee(process);
}

SYSCALL_DEFINE1(clone, unsigned long, clone_flags)
{
    printf("%s(%lu) from %d\n", __func__, clone_flags, process->pid);

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
        printf("success pid=%d\n", newpid);

        //unsigned long hnp_flags = 0;
        if(clone_flags&CLONE_VM)
            printf("CLONE_VM\n");
        if((clone_flags&CSIGNAL) != SIGCHLD )
            printf("SIGCHLD\n");
        if(clone_flags&CLONE_THREAD)
            printf("CLONE_THREAD\n");

        //pid_t parent = state->m_tid;
        if((clone_flags&CLONE_PARENT) || (clone_flags&CLONE_THREAD))
            printf("CLONE_PARENT || CLONE_THREAD\n");
            //parent = state->m_ppid;

        syshook_handle_new_process(process->context, process->pid, newpid);
    } else {
        printf("error: %d\n", newpid);
    }



    return newpid;
}

SYSCALL_DEFINE3(execve, const char __user *, path,
		const char __user *const __user *, argv,
		const char __user *const __user *, envp)
{
    (void)(path);
    (void)(argv);
    (void)(envp);

    printf("%s\n", __func__);
    long rc = syshook_invoke_hookee(process);
    process->expect_execve = true;

    return rc;
}

#if 0
SYSCALL_DEFINE2(openat, int, dirfd, const char __user*, pathname)
{
    char pathname_k[PATH_MAX];
    syshook_strncpy_user(process, pathname_k, pathname, PATH_MAX);

    // allocate memory
    void __user* addr = (void*)syshook_invoke_syscall(process, SYS_mmap2, NULL, process->context->pagesize, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

    // replace args
    if(!strcmp(pathname_k, "/proc/mounts")) {
        const char* newpath = "/default.prop";
        syshook_copy_to_user(process, addr, newpath, strlen(newpath)+1);
        syshook_argument_set(process, 1, (long)addr);
    }

    // caal hookee
    printf("%s(%d, %s) = ", __func__, dirfd, pathname_k);
    long rc;
    rc = syshook_invoke_hookee(process);
    printf("%d\n", (int)rc);

    // free memory
    syshook_invoke_syscall(process, SYS_munmap, addr, process->context->pagesize);

    return rc;
}
#endif

SYSCALL_DEFINE0(getuid32)
{
    return 1000;
}

#define register_syscall(name) sys_call_table[SYS_##name] = sys_##name;

int main(int argc, char** argv) {

    // register syscalls
    register_syscall(fork);
    register_syscall(vfork);
    register_syscall(clone);
    register_syscall(execve);
    register_syscall(getuid32);
    //register_syscall(openat);

    // start syshook
    if(argc<=1) {
        char *par[2];
        int i = 0;

        // build args
        par[i++] = "/init";
        par[i++] = (char *)0;

        return syshook_execve(par, sys_call_table);
    }

    return syshook_execve(argv+1, sys_call_table);
}
