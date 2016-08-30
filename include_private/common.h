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
#include <sys/syscall.h>
#include <linux/sched.h>
#include <pthread.h>

#include <syshook.h>
#include <syshook/private/arch.h>

#define LOG_TAG "LIBSYSHOOK"
#include <lib/log.h>

// common macros
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(*(a)))
#define ROUNDUP(a, b) (((a) + ((b)-1)) & ~((b)-1))
#define ROUNDDOWN(a, b) ((a) & ~((b)-1))
#define STRCASE(a) case a: return #a;
#define STRFLAGCPY(buf, n, flags, a) \
    if((flags)&(a)){ \
        size_t bytes = snprintf((buf), (n), "|%s", #a); \
        if(bytes>0) { \
            buf += bytes; \
            n   -= bytes; \
        } \
    }

#define INJECTION_DECLARE(name) \
    extern int name; \
    extern int name##_end;

#define INJECTION_PTR(name) ((void*)&name)
#define INJECTION_SIZE(name) ((unsigned)(((void*)&name##_end) - ((void*)&name)))

typedef enum {
    STATUS_TYPE_EXIT = 0x1,
    STATUS_TYPE_CLONE = 0x2,
    STATUS_TYPE_SYSCALL= 0x4,
    STATUS_TYPE_EXEC = 0x8,
    STATUS_TYPE_EXEC_OTHER = 0x10,
    STATUS_TYPE_OTHER = 0x20,
} status_type_t;
#define STATUS_TYPE_ALL 0xffff

#define THREAD_EXIT_CODE_STOP 1
#define THREAD_EXIT_CODE_EXEC 2
#define THREAD_EXIT_CODE_ERROR 3

typedef struct {
    status_type_t type;

    // all
    int signal;

    // clone
    unsigned long data;
} parsed_status_t;

void syshook_wait_for_signal(syshook_process_t* process, parsed_status_t* parsed_status);
void syshook_handle_child_signal(syshook_process_t* process, parsed_status_t* parsed_status, status_type_t retsignals);
void syshook_register_defaults(syshook_context_t* context);
syshook_context_t* syshook_get_thread_context(void);
syshook_process_t* get_thread_process(void);
void syshook_thread_exit(int code);

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
        STRCASE(SIGUSR1);
        STRCASE(SIGSEGV);
        STRCASE(SIGUSR2);
        STRCASE(SIGPIPE);
        STRCASE(SIGALRM);
        STRCASE(SIGTERM);
        STRCASE(SIGSTKFLT);
        STRCASE(SIGCHLD);
        STRCASE(SIGCONT);
        STRCASE(SIGSTOP);
        STRCASE(SIGTSTP);
        STRCASE(SIGTTIN);
        STRCASE(SIGTTOU);
        STRCASE(SIGURG);
        STRCASE(SIGXCPU);
        STRCASE(SIGXFSZ);
        STRCASE(SIGVTALRM);
        STRCASE(SIGPROF);
        STRCASE(SIGWINCH);
        STRCASE(SIGIO);
        STRCASE(SIGPWR);
        STRCASE(SIGSYS);
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

static inline const char *ptracerequest2str(enum __ptrace_request request){
    switch(request) {
        STRCASE(PTRACE_TRACEME);
        STRCASE(PTRACE_PEEKTEXT);
        STRCASE(PTRACE_PEEKDATA);
        STRCASE(PTRACE_PEEKUSER);
        STRCASE(PTRACE_POKETEXT);
        STRCASE(PTRACE_POKEDATA);
        STRCASE(PTRACE_POKEUSER);
        STRCASE(PTRACE_CONT);
        STRCASE(PTRACE_KILL);
        STRCASE(PTRACE_SINGLESTEP);
        STRCASE(PTRACE_GETREGS);
        STRCASE(PTRACE_SETREGS);
        STRCASE(PTRACE_GETFPREGS);
        STRCASE(PTRACE_SETFPREGS);
        STRCASE(PTRACE_ATTACH);
        STRCASE(PTRACE_DETACH);
        STRCASE(PTRACE_GETFPXREGS);
        STRCASE(PTRACE_SETFPXREGS);
        STRCASE(PTRACE_SYSCALL);
        STRCASE(PTRACE_SETOPTIONS);
        STRCASE(PTRACE_GETEVENTMSG);
        STRCASE(PTRACE_GETSIGINFO);
        STRCASE(PTRACE_SETSIGINFO);
        STRCASE(PTRACE_GETREGSET);
        STRCASE(PTRACE_SETREGSET);
        STRCASE(PTRACE_SEIZE);
        STRCASE(PTRACE_INTERRUPT);
        STRCASE(PTRACE_PEEKSIGINFO);

    default:
        return "unknown";
    }
}

// safety wrappers

static inline pid_t safe_fork(void) {
    pid_t pid = fork();
    if(pid<0) {
        LOGF("fork: %s\n", strerror(errno));
    }

    return pid;
}

static inline long safe_ptrace_ex(enum __ptrace_request request, pid_t pid,
                   void *addr, void *data, int return_when_notfound)
{
    // clear errno
    errno = 0;

    long ret = ptrace(request, pid, addr, data);
    if(errno) {
        // No such process
        if(errno==ESRCH) {
            if(return_when_notfound)
                return ret;

            LOGV("ptrace(%s, %d, %p, %p): %s\n", ptracerequest2str(request), pid, addr, data, strerror(errno));
            syshook_thread_exit(THREAD_EXIT_CODE_ERROR);
        }

        LOGF("ptrace(%s, %d, %p, %p): %s\n", ptracerequest2str(request), pid, addr, data, strerror(errno));
    }

    return ret;
}

static inline long safe_ptrace(enum __ptrace_request request, pid_t pid,
                   void *addr, void *data)
{
    return safe_ptrace_ex(request, pid, addr, data, 0);
}

static inline pid_t safe_waitpid(pid_t pid, int *stat_loc, int options) {
    *stat_loc = 0;

    pid_t ret = waitpid(pid, stat_loc, options);
    if(ret==-1 || (pid!=-1 && ret!=pid)) {
        LOGF("waitpid: %s\n", strerror(errno));
    }

    return ret;
}

static inline void* safe_malloc(size_t size) {
    void* mem = malloc(size);
    if(!mem) {
        LOGF("malloc: %s\n", strerror(errno));
    }

    return mem;
}

static inline void* safe_calloc(size_t num, size_t size) {
    void* mem = calloc(num, size);
    if(!mem) {
        LOGF("calloc: %s\n", strerror(errno));
    }

    return mem;
}

#endif
