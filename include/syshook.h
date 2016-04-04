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
#include <pthread.h>
#include <sys/ptrace.h>

#include <syshook/list.h>
#include <syshook/syscalls.h>

#define SYSHOOK_NUM_SYSCALLS 2048

typedef struct {
    int pagesize;
    list_node_t processes;
    list_node_t queue;
    void** sys_call_table;

    pthread_t main_thread;
    pthread_mutex_t lock;
} syshook_context_t;

typedef struct {
    // list
    list_node_t node;

    // thread
    pthread_t thread;
    bool should_stop;

    // ptrace queue
    list_node_t queue_node;
    pthread_mutex_t queue_mutex;
    pthread_cond_t queue_cond;

    enum __ptrace_request ptrace_request;
    pid_t ptrace_pid;
    void* ptrace_addr;
    void* ptrace_data;

    long ptrace_rc;

    // info
    syshook_context_t* context;
    pid_t pid;
    pid_t ppid;
    bool sigstop_received;
    bool expect_execve;

    // status
    void* original_state;
    void* state;
} syshook_process_t;

// syshook init
int syshook_execve(char **argv, void** sys_call_table);

// syscall invocation
long syshook_invoke_hookee(syshook_process_t* process);
long syshook_invoke_syscall(syshook_process_t* process, long scno, ...);

// argument modification
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
