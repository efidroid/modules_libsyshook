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

#ifndef _COMMON_H_
#define _COMMON_H_

#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include <syshook.h>
#include <syshook/private/arch.h>

// common macros
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(*(a)))
#define STRCASE(a) case a: return #a;

// logging
//#define LOGE(fmt, ...) fprintf(stderr, "[%s:%u] " fmt, __func__, __LINE__, ##__VA_ARGS__)
#define LOGE(fmt, ...) fprintf(stderr, "[%lu] " fmt, pthread_self(), ##__VA_ARGS__); fflush(stderr);
//#define LOGE(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__); fflush(stderr);
#define LOGD LOGE

typedef enum {
    STATUS_TYPE_EXIT,
    STATUS_TYPE_CLONE,
    STATUS_TYPE_SYSCALL,
    STATUS_TYPE_OTHER,
} status_type_t;

typedef struct {
    status_type_t type;

    // all
    int signal;

    // clone, syscall
    siginfo_t siginfo;
    unsigned long data;
    int ptrace_event;
} parsed_status_t;

// string conversion
static inline const char *sig2str( int signum ) {
    switch(signum) {
        STRCASE(SIGHUP);
        STRCASE(SIGINT);
        STRCASE(SIGQUIT);
        STRCASE(SIGILL);
        STRCASE(SIGTRAP);
        STRCASE(SIGABRT);
        STRCASE(SIGBUS);
        STRCASE(SIGFPE);
        STRCASE(SIGKILL);
        STRCASE(SIGSEGV);
        STRCASE(SIGPIPE);
        STRCASE(SIGALRM);
        STRCASE(SIGTERM);
        STRCASE(SIGCHLD);
        STRCASE(SIGCONT);
        STRCASE(SIGSTOP);
    default:
        return "unknown";
    }
}

static inline const char *ptraceevent2str(int event){
    switch(event) {
        STRCASE(PTRACE_EVENT_VFORK);
        STRCASE(PTRACE_EVENT_FORK);
        STRCASE(PTRACE_EVENT_CLONE);
        STRCASE(PTRACE_EVENT_VFORK_DONE);
        STRCASE(PTRACE_EVENT_EXEC);
        STRCASE(PTRACE_EVENT_EXIT);
        STRCASE(PTRACE_EVENT_SECCOMP);
    default:
        return "unknown";
    }
}

// safety wrappers

static inline __attribute__((noreturn)) void safe_exit(int status) {
    exit(status);
    for(;;);
}

static inline pid_t safe_fork(void) {
    pid_t pid = fork();
    if(pid<0) {
        LOGE("fork: %s\n", strerror(-pid));
        safe_exit(-1);
    }

    return pid;
}

static inline long safe_ptrace(enum __ptrace_request request, pid_t pid,
                   void *addr, void *data)
{
    // clear errno
    errno = 0;

    long ret = ptrace(request, pid, addr, data);
    if(errno) {
        perror("ptrace");
        safe_exit(-1);
    }

    return ret;
}

static inline pid_t safe_waitpid(pid_t pid, int *stat_loc, int options) {
    pid_t ret = waitpid(pid, stat_loc, options);
    if(ret==-1 || (pid!=-1 && ret!=pid)) {
        perror("waitpid");
        safe_exit(-1);
    }

    return ret;
}

static inline void* safe_malloc(size_t size) {
    void* mem = malloc(size);
    if(!mem) {
        perror("malloc");
        safe_exit(-1);
    }

    return mem;
}

static inline void* safe_calloc(size_t num, size_t size) {
    void* mem = calloc(num, size);
    if(!mem) {
        perror("calloc");
        safe_exit(-1);
    }

    return mem;
}

void syshook_parse_child_signal(syshook_process_t* process, int status, parsed_status_t* pstatus);
syshook_process_t* syshook_handle_new_process(syshook_context_t* context, pid_t ppid, pid_t pid);

long queue_ptrace(syshook_process_t* process, enum __ptrace_request request, pid_t pid,
                   void *addr, void *data);

#endif
