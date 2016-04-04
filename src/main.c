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

static void* sys_call_table[SYSHOOK_NUM_SYSCALLS] = {0};

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
    //printf("%s(%d, %s) = ", __func__, dirfd, pathname_k);
    long rc = syshook_invoke_hookee(process);
    //printf("%d\n", (int)rc);

    // free memory
    syshook_invoke_syscall(process, SYS_munmap, addr, process->context->pagesize);

    return rc;
}

SYSCALL_DEFINE0(getuid32)
{
    return 1000;
}

#define register_syscall(name) sys_call_table[SYS_##name] = sys_##name;

int main(int argc, char** argv) {

    // register syscalls
    //register_syscall(getuid32);
    register_syscall(openat);

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
