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

#ifndef _SYSHOOK_H_
#define _SYSHOOK_H_

#include <unistd.h>
#include <stdint.h>
#include <setjmp.h>

#include <syshook/list.h>
#include <syshook/syscalls.h>

#define SYSHOOK_NUM_SYSCALLS 2048

typedef struct syshook_context syshook_context_t;
typedef struct syshook_process syshook_process_t;

struct syshook_context {
    int pagesize;
    syshook_list_node_t processes;
    void** sys_call_table;
    long ptrace_options;

    // threading
    pthread_mutex_t lock;

    // callbacks
    int (*create_process)(syshook_process_t*);
    int (*destroy_process)(syshook_process_t*);
    int (*execve_process)(syshook_process_t*);
};

struct syshook_process {
    // list
    syshook_list_node_t node;

    // info
    syshook_context_t* context;
    pid_t pid;
    pid_t tid;
    pid_t ppid;
    pid_t creatorpid;
    bool sigstop_received;
    bool expect_execve;
    bool expect_syscall_exit;
    unsigned long clone_flags;
    void* exit_handler;

    // status
    void* original_state;
    void* state;
    bool stopped;

    // threading
    pthread_t thread;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    jmp_buf jmpbuf;

    long handler_context[10];

    // pdata of libsyshook users
    void* pdata;
};

// syshook init
int syshook_execvp(char **argv, void** sys_call_table);

// syscall invocation
long syshook_invoke_hookee(syshook_process_t* process);
long syshook_invoke_syscall(syshook_process_t* process, long scno, ...);
bool syshook_is_entry(syshook_process_t* process);

// argument modification
void syshook_syscall_set(syshook_process_t* process, int scno);
long syshook_result_get(syshook_process_t* process);
long syshook_argument_get(syshook_process_t* process, int num);
void syshook_argument_set(syshook_process_t* process, int num, long value);

long syshook_copy_from_user(syshook_process_t* process, void *to, const void __user * from, unsigned long n);
long syshook_copy_to_user(syshook_process_t* process, void __user *to, const void *from, unsigned long n);

/*
 * strndup_user - duplicate an existing string from user space
 * @s: The string to duplicate
 * @n: Maximum number of bytes to copy, including the trailing NUL.
 */
char* syshook_strndup_user(syshook_process_t* process, const char __user *s, long n);
long syshook_strncpy_user(syshook_process_t* process, char *to, const char __user *from, long n);


#endif // _SYSHOOK_H_
