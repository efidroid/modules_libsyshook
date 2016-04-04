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
#include <arch.h>

// common macros
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(*(a)))
#define STRCASE(a) case a: return #a;

// logging
#define LOGE(x...) fprintf(stderr, x)
#define LOGD LOGE

// string conversion
static const char *sig2str( int signum ) {
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

static const char *ptraceevent2str(int event){
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

#define asmlinkage

/**
 * BUILD_BUG_ON - break compile if a condition is true.
 * @condition: the condition which the compiler should know is false.
 *
 * If you have some code which relies on certain constants being equal, or
 * other compile-time-evaluated condition, you should use BUILD_BUG_ON to
 * detect if someone changes it.
 *
 * The implementation uses gcc's reluctance to create a negative array, but
 * gcc (as of 4.4) only emits that error for obvious cases (eg. not arguments
 * to inline functions).  So as a fallback we use the optimizer; if it can't
 * prove the condition is false, it will cause a link error on the undefined
 * "__build_bug_on_failed".  This error message can be harder to track down
 * though, hence the two different methods.
 */
#ifndef __OPTIMIZE__
#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))
#else
extern int __build_bug_on_failed;
#define BUILD_BUG_ON(condition)					\
	do {							\
		((void)sizeof(char[1 - 2*!!(condition)]));	\
		if (condition) __build_bug_on_failed = 1;	\
	} while(0)
#endif

#define __SC_DECL1(t1, a1)	t1 a1
#define __SC_DECL2(t2, a2, ...) t2 a2, __SC_DECL1(__VA_ARGS__)
#define __SC_DECL3(t3, a3, ...) t3 a3, __SC_DECL2(__VA_ARGS__)
#define __SC_DECL4(t4, a4, ...) t4 a4, __SC_DECL3(__VA_ARGS__)
#define __SC_DECL5(t5, a5, ...) t5 a5, __SC_DECL4(__VA_ARGS__)
#define __SC_DECL6(t6, a6, ...) t6 a6, __SC_DECL5(__VA_ARGS__)

#define __SC_LONG1(t1, a1) 	long a1
#define __SC_LONG2(t2, a2, ...) long a2, __SC_LONG1(__VA_ARGS__)
#define __SC_LONG3(t3, a3, ...) long a3, __SC_LONG2(__VA_ARGS__)
#define __SC_LONG4(t4, a4, ...) long a4, __SC_LONG3(__VA_ARGS__)
#define __SC_LONG5(t5, a5, ...) long a5, __SC_LONG4(__VA_ARGS__)
#define __SC_LONG6(t6, a6, ...) long a6, __SC_LONG5(__VA_ARGS__)

#define __SC_CAST1(t1, a1)	(t1) a1
#define __SC_CAST2(t2, a2, ...) (t2) a2, __SC_CAST1(__VA_ARGS__)
#define __SC_CAST3(t3, a3, ...) (t3) a3, __SC_CAST2(__VA_ARGS__)
#define __SC_CAST4(t4, a4, ...) (t4) a4, __SC_CAST3(__VA_ARGS__)
#define __SC_CAST5(t5, a5, ...) (t5) a5, __SC_CAST4(__VA_ARGS__)
#define __SC_CAST6(t6, a6, ...) (t6) a6, __SC_CAST5(__VA_ARGS__)

#define __SC_TEST(type)		BUILD_BUG_ON(sizeof(type) > sizeof(long))
#define __SC_TEST1(t1, a1)	__SC_TEST(t1)
#define __SC_TEST2(t2, a2, ...)	__SC_TEST(t2); __SC_TEST1(__VA_ARGS__)
#define __SC_TEST3(t3, a3, ...)	__SC_TEST(t3); __SC_TEST2(__VA_ARGS__)
#define __SC_TEST4(t4, a4, ...)	__SC_TEST(t4); __SC_TEST3(__VA_ARGS__)
#define __SC_TEST5(t5, a5, ...)	__SC_TEST(t5); __SC_TEST4(__VA_ARGS__)
#define __SC_TEST6(t6, a6, ...)	__SC_TEST(t6); __SC_TEST5(__VA_ARGS__)

#define SYSCALL_DEFINE0(name)	   asmlinkage long sys_##name(__attribute__((unused)) process_t* process)
#define SYSCALL_DEFINE1(name, ...) SYSCALL_DEFINEx(1, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE2(name, ...) SYSCALL_DEFINEx(2, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE3(name, ...) SYSCALL_DEFINEx(3, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE4(name, ...) SYSCALL_DEFINEx(4, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE5(name, ...) SYSCALL_DEFINEx(5, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE6(name, ...) SYSCALL_DEFINEx(6, _##name, __VA_ARGS__)

#define SYSCALL_ALIAS(alias, name)					\
	asm ("\t.globl " #alias "\n\t.set " #alias ", " #name)

#define SYSCALL_DEFINEx(x, sname, ...)				\
	__SYSCALL_DEFINEx(x, sname, __VA_ARGS__)

#define __SYSCALL_DEFINEx(x, name, ...)					\
	asmlinkage long sys##name(process_t* process, __SC_DECL##x(__VA_ARGS__));		\
	static inline long SYSC##name(process_t* process, __SC_DECL##x(__VA_ARGS__));	\
	asmlinkage long SyS##name(process_t* process, __SC_LONG##x(__VA_ARGS__))		\
	{								\
		__SC_TEST##x(__VA_ARGS__);				\
		return (long) SYSC##name(process, __SC_CAST##x(__VA_ARGS__));	\
	}								\
	SYSCALL_ALIAS(sys##name, SyS##name);				\
	static inline long SYSC##name(__attribute__((unused)) process_t* process, __SC_DECL##x(__VA_ARGS__))

#endif
