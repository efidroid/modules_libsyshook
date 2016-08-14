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

#ifndef _PLATFORM_H_
#define _PLATFORM_H_

#include <stdbool.h>

typedef struct {
    bool lowargs_changed;
    bool highargs_changed;
    bool scno_changed;
    bool result_changed;
    long result;
    char regs[0];
} syshook_internal_t;

#define PLATFORM_STATE_SIZE (sizeof(syshook_internal_t) + (18*4))

void syshook_arch_get_state(syshook_process_t* process, void* state);
void syshook_arch_set_state(syshook_process_t* process, void* state);
void syshook_arch_copy_state(void* dst, void* src);

long syshook_arch_get_pc(void* state);
void syshook_arch_set_pc(void* state, long pc);
long syshook_arch_get_instruction_size(unsigned long instr);

bool syshook_arch_is_entry(void* state);
int syshook_arch_syscall_get(void* state);
void syshook_arch_syscall_set(void* state, int scno);
long syshook_arch_argument_get(void* state, int num);
void syshook_arch_argument_set(void* state, int num, long value);
long syshook_arch_result_get(void* state);
void syshook_arch_result_set(void* state, long value);

void syshook_arch_setup_process_trap(syshook_process_t* process);

#endif
