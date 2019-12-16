/*
 * Copyright 2015 Big Switch Networks, Inc
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

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <inttypes.h>
#include <sys/mman.h>
#include "ubpf_int.h"

#define MAX_EXT_FUNCS 128
#define OOB_CALL 0x3f
#define MAX_LOAD_STORE 2048
#define ADDED_LOAD_STORE_INSTS 22
#define ADDED_CTX_CALL 12
#define MAX_CALL 2048

static bool validate(const struct ubpf_vm *vm, const struct ebpf_inst *insts, uint32_t num_insts, char **errmsg, uint32_t *num_load_store, int *rewrite_pcs);
static bool rewrite_with_memchecks(struct ubpf_vm *vm, const struct ebpf_inst *insts, uint32_t num_insts, char **errmsg, uint64_t memory_ptr, uint32_t memory_size, uint32_t num_load_store, int *rewrite_pcs);
static bool bounds_check(struct ubpf_vm *vm, void *addr, int size, const char *type, uint16_t cur_pc, void *mem, size_t mem_len, void *stack);
static bool rewrite_with_ctx(struct ubpf_vm *vm, const struct ebpf_inst *insts, uint32_t num_inst, char **errmsg, uint64_t ctx_id);

struct ubpf_vm *
ubpf_create(void)
{
    struct ubpf_vm *vm = calloc(1, sizeof(*vm));
    if (vm == NULL) {
        return NULL;
    }

    vm->ext_funcs = calloc(MAX_EXT_FUNCS, sizeof(*vm->ext_funcs));
    if (vm->ext_funcs == NULL) {
        ubpf_destroy(vm);
        return NULL;
    }

    vm->ext_func_names = calloc(MAX_EXT_FUNCS, sizeof(*vm->ext_func_names));
    if (vm->ext_func_names == NULL) {
        ubpf_destroy(vm);
        return NULL;
    }

    vm->first_mem_node = NULL;

    // will be filled in ubpf_load
    vm->extra_mem_size = 0;
    vm->extra_mem_start = NULL;

    return vm;
}

void
ubpf_destroy(struct ubpf_vm *vm)
{
    if (vm->jitted) {
        munmap(vm->jitted, vm->jitted_size);
    }
    free(vm->insts);
    free(vm->ext_funcs);
    free(vm->ext_func_names);

    static_mem_node_t *n = vm->first_mem_node;
    static_mem_node_t *tmp;
    while (n) {
        tmp = n;
        n = n->next;
        free(tmp->ptr);
        free(tmp);
    }
    free(vm);
}

int
ubpf_register(struct ubpf_vm *vm, unsigned int idx, const char *name, void *fn)
{
    if (idx >= MAX_EXT_FUNCS) {
        return -1;
    }

    vm->ext_funcs[idx] = (ext_func)fn;
    vm->ext_func_names[idx] = name;
    return 0;
}

unsigned int
ubpf_lookup_registered_function(struct ubpf_vm *vm, const char *name)
{
    int i;
    for (i = 0; i < MAX_EXT_FUNCS; i++) {
        const char *other = vm->ext_func_names[i];
        if (other && !strcmp(other, name)) {
            return i;
        }
    }
    return -1;
}

int
ubpf_load(struct ubpf_vm *vm, const void *code, uint32_t code_len, char **errmsg, uint64_t memory_ptr, uint32_t memory_size, uint64_t ctx_id)
{
    *errmsg = NULL;
    uint32_t num_load_store = 0;
    int rewrite_pcs[MAX_LOAD_STORE];

    if (vm->insts) {
        *errmsg = ubpf_error("code has already been loaded into this VM");
        return -1;
    }

    if (code_len % 8 != 0) {
        *errmsg = ubpf_error("code_len must be a multiple of 8");
        return -1;
    }

    if (!validate(vm, code, code_len/8, errmsg, &num_load_store, rewrite_pcs)) {
        return -1;
    }

    if (memory_ptr != 0 && memory_size != 0) {
        vm->insts = malloc(code_len + (8 * ADDED_LOAD_STORE_INSTS) * num_load_store); /* 22 instructions by memcheck */
        if (vm->insts == NULL) {
            *errmsg = ubpf_error("out of memory");
            return -1;
        }

        vm->extra_mem_start = (void *) memory_ptr;
        vm->extra_mem_size = memory_size;

        rewrite_with_memchecks(vm, code, code_len/8, errmsg, memory_ptr, memory_size, num_load_store, rewrite_pcs);
        vm->num_insts = code_len/sizeof(vm->insts[0]) + (ADDED_LOAD_STORE_INSTS * num_load_store);
    } else {
        vm->insts = malloc(code_len);
        if (vm->insts == NULL) {
            *errmsg = ubpf_error("out of memory");
            return -1;
        }

        memcpy(vm->insts, code, code_len);
        vm->num_insts = code_len/sizeof(vm->insts[0]);
    }

    if(ctx_id != 0) {
        struct ebpf_inst *code_ptr = vm->insts;
        if (!rewrite_with_ctx(vm, code_ptr, vm->num_insts, errmsg, ctx_id)) {
            return -1;
        }
        free(code_ptr);
    }

    return 0;
}

static uint32_t
u32(uint64_t x)
{
    return x;
}

const char *ubpf_get_error_msg(const struct ubpf_vm *vm) {
    return vm->error_msg[0] ? vm->error_msg : NULL;
}

uint64_t
ubpf_exec(struct ubpf_vm *vm, void *mem, size_t mem_len)
{
    return ubpf_exec_with_arg(vm, mem, mem, mem_len);
}

uint64_t
ubpf_exec_with_arg(struct ubpf_vm *vm, void *arg, void *mem, size_t mem_len)
{
    uint16_t pc = 0;
    const struct ebpf_inst *insts = vm->insts;
    uint64_t reg[16];
    uint64_t stack[(STACK_SIZE+7)/8];

    if (!insts) {
        /* Code must be loaded before we can execute */
        return UINT64_MAX;
    }

    reg[1] = (uintptr_t)arg;
    reg[10] = (uintptr_t)stack + sizeof(stack);

    while (1) {
        const uint16_t cur_pc = pc;
        struct ebpf_inst inst = insts[pc++];

        switch (inst.opcode) {
        case EBPF_OP_ADD_IMM:
            reg[inst.dst] += inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_ADD_REG:
            reg[inst.dst] += reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_SUB_IMM:
            reg[inst.dst] -= inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_SUB_REG:
            reg[inst.dst] -= reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_MUL_IMM:
            reg[inst.dst] *= inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_MUL_REG:
            reg[inst.dst] *= reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_DIV_IMM:
            reg[inst.dst] = u32(reg[inst.dst]) / u32(inst.imm);
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_DIV_REG:
            if (reg[inst.src] == 0) {
                snprintf(vm->error_msg, MAX_ERROR_MSG, "uBPF error: division by zero at PC %u\n", cur_pc);
                fprintf(stderr, "%s", vm->error_msg);
                return UINT64_MAX;
            }
            reg[inst.dst] = u32(reg[inst.dst]) / u32(reg[inst.src]);
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_OR_IMM:
            reg[inst.dst] |= inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_OR_REG:
            reg[inst.dst] |= reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_AND_IMM:
            reg[inst.dst] &= inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_AND_REG:
            reg[inst.dst] &= reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_LSH_IMM:
            reg[inst.dst] <<= inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_LSH_REG:
            reg[inst.dst] <<= reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_RSH_IMM:
            reg[inst.dst] = u32(reg[inst.dst]) >> inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_RSH_REG:
            reg[inst.dst] = u32(reg[inst.dst]) >> reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_NEG:
            reg[inst.dst] = -reg[inst.dst];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_MOD_IMM:
            reg[inst.dst] = u32(reg[inst.dst]) % u32(inst.imm);
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_MOD_REG:
            if (reg[inst.src] == 0) {
                snprintf(vm->error_msg, MAX_ERROR_MSG, "uBPF error: division by zero at PC %u\n", cur_pc);
                fprintf(stderr, "%s", vm->error_msg);
                return UINT64_MAX;
            }
            reg[inst.dst] = u32(reg[inst.dst]) % u32(reg[inst.src]);
            break;
        case EBPF_OP_XOR_IMM:
            reg[inst.dst] ^= inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_XOR_REG:
            reg[inst.dst] ^= reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_MOV_IMM:
            reg[inst.dst] = inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_MOV_REG:
            reg[inst.dst] = reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_ARSH_IMM:
            reg[inst.dst] = (int32_t)reg[inst.dst] >> inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_ARSH_REG:
            reg[inst.dst] = (int32_t)reg[inst.dst] >> u32(reg[inst.src]);
            reg[inst.dst] &= UINT32_MAX;
            break;

        case EBPF_OP_LE:
            if (inst.imm == 16) {
                reg[inst.dst] = htole16(reg[inst.dst]);
            } else if (inst.imm == 32) {
                reg[inst.dst] = htole32(reg[inst.dst]);
            } else if (inst.imm == 64) {
                reg[inst.dst] = htole64(reg[inst.dst]);
            }
            break;
        case EBPF_OP_BE:
            if (inst.imm == 16) {
                reg[inst.dst] = htobe16(reg[inst.dst]);
            } else if (inst.imm == 32) {
                reg[inst.dst] = htobe32(reg[inst.dst]);
            } else if (inst.imm == 64) {
                reg[inst.dst] = htobe64(reg[inst.dst]);
            }
            break;


        case EBPF_OP_ADD64_IMM:
            reg[inst.dst] += inst.imm;
            break;
        case EBPF_OP_ADD64_REG:
            reg[inst.dst] += reg[inst.src];
            break;
        case EBPF_OP_SUB64_IMM:
            reg[inst.dst] -= inst.imm;
            break;
        case EBPF_OP_SUB64_REG:
            reg[inst.dst] -= reg[inst.src];
            break;
        case EBPF_OP_MUL64_IMM:
            reg[inst.dst] *= inst.imm;
            break;
        case EBPF_OP_MUL64_REG:
            reg[inst.dst] *= reg[inst.src];
            break;
        case EBPF_OP_DIV64_IMM:
            reg[inst.dst] /= inst.imm;
            break;
        case EBPF_OP_DIV64_REG:
            if (reg[inst.src] == 0) {
                snprintf(vm->error_msg, MAX_ERROR_MSG, "uBPF error: division by zero at PC %u\n", cur_pc);
                fprintf(stderr, "%s", vm->error_msg);
                return UINT64_MAX;
            }
            reg[inst.dst] /= reg[inst.src];
            break;
        case EBPF_OP_OR64_IMM:
            reg[inst.dst] |= inst.imm;
            break;
        case EBPF_OP_OR64_REG:
            reg[inst.dst] |= reg[inst.src];
            break;
        case EBPF_OP_AND64_IMM:
            reg[inst.dst] &= inst.imm;
            break;
        case EBPF_OP_AND64_REG:
            reg[inst.dst] &= reg[inst.src];
            break;
        case EBPF_OP_LSH64_IMM:
            reg[inst.dst] <<= inst.imm;
            break;
        case EBPF_OP_LSH64_REG:
            reg[inst.dst] <<= reg[inst.src];
            break;
        case EBPF_OP_RSH64_IMM:
            reg[inst.dst] >>= inst.imm;
            break;
        case EBPF_OP_RSH64_REG:
            reg[inst.dst] >>= reg[inst.src];
            break;
        case EBPF_OP_NEG64:
            reg[inst.dst] = -reg[inst.dst];
            break;
        case EBPF_OP_MOD64_IMM:
            reg[inst.dst] %= inst.imm;
            break;
        case EBPF_OP_MOD64_REG:
            if (reg[inst.src] == 0) {
                snprintf(vm->error_msg, MAX_ERROR_MSG, "uBPF error: division by zero at PC %u\n", cur_pc);
                fprintf(stderr, "%s", vm->error_msg);
                return UINT64_MAX;
            }
            reg[inst.dst] %= reg[inst.src];
            break;
        case EBPF_OP_XOR64_IMM:
            reg[inst.dst] ^= inst.imm;
            break;
        case EBPF_OP_XOR64_REG:
            reg[inst.dst] ^= reg[inst.src];
            break;
        case EBPF_OP_MOV64_IMM:
            reg[inst.dst] = inst.imm;
            break;
        case EBPF_OP_MOV64_REG:
            reg[inst.dst] = reg[inst.src];
            break;
        case EBPF_OP_ARSH64_IMM:
            reg[inst.dst] = (int64_t)reg[inst.dst] >> inst.imm;
            break;
        case EBPF_OP_ARSH64_REG:
            reg[inst.dst] = (int64_t)reg[inst.dst] >> reg[inst.src];
            break;

        /*
         * HACK runtime bounds check
         *
         * Needed since we don't have a verifier yet.
         */
#define BOUNDS_CHECK_LOAD(size) \
    do { \
        if (!bounds_check(vm, (void *)reg[inst.src] + inst.offset, size, "load", cur_pc, mem, mem_len, stack)) { \
            return UINT64_MAX; \
        } \
    } while (0)
#define BOUNDS_CHECK_STORE(size) \
    do { \
        if (!bounds_check(vm, (void *)reg[inst.dst] + inst.offset, size, "store", cur_pc, mem, mem_len, stack)) { \
            return UINT64_MAX; \
        } \
    } while (0)

        case EBPF_OP_LDXW:
            BOUNDS_CHECK_LOAD(4);
            reg[inst.dst] = *(uint32_t *)(uintptr_t)(reg[inst.src] + inst.offset);
            break;
        case EBPF_OP_LDXH:
            BOUNDS_CHECK_LOAD(2);
            reg[inst.dst] = *(uint16_t *)(uintptr_t)(reg[inst.src] + inst.offset);
            break;
        case EBPF_OP_LDXB:
            BOUNDS_CHECK_LOAD(1);
            reg[inst.dst] = *(uint8_t *)(uintptr_t)(reg[inst.src] + inst.offset);
            break;
        case EBPF_OP_LDXDW:
            BOUNDS_CHECK_LOAD(8);
            reg[inst.dst] = *(uint64_t *)(uintptr_t)(reg[inst.src] + inst.offset);
            break;

        case EBPF_OP_STW:
            BOUNDS_CHECK_STORE(4);
            *(uint32_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = inst.imm;
            break;
        case EBPF_OP_STH:
            BOUNDS_CHECK_STORE(2);
            *(uint16_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = inst.imm;
            break;
        case EBPF_OP_STB:
            BOUNDS_CHECK_STORE(1);
            *(uint8_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = inst.imm;
            break;
        case EBPF_OP_STDW:
            BOUNDS_CHECK_STORE(8);
            *(uint64_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = inst.imm;
            break;

        case EBPF_OP_STXW:
            BOUNDS_CHECK_STORE(4);
            *(uint32_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = reg[inst.src];
            break;
        case EBPF_OP_STXH:
            BOUNDS_CHECK_STORE(2);
            *(uint16_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = reg[inst.src];
            break;
        case EBPF_OP_STXB:
            BOUNDS_CHECK_STORE(1);
            *(uint8_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = reg[inst.src];
            break;
        case EBPF_OP_STXDW:
            BOUNDS_CHECK_STORE(8);
            *(uint64_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = reg[inst.src];
            break;

        case EBPF_OP_LDDW:
            reg[inst.dst] = (uint32_t)inst.imm | ((uint64_t)insts[pc++].imm << 32);
            break;

        case EBPF_OP_JA:
            pc += inst.offset;
            break;
        case EBPF_OP_JEQ_IMM:
            if (reg[inst.dst] == inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JEQ_REG:
            if (reg[inst.dst] == reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JGT_IMM:
            if (reg[inst.dst] > (uint32_t)inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JGT_REG:
            if (reg[inst.dst] > reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JGE_IMM:
            if (reg[inst.dst] >= (uint32_t)inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JGE_REG:
            if (reg[inst.dst] >= reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JLT_IMM:
            if (reg[inst.dst] < (uint32_t)inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JLT_REG:
            if (reg[inst.dst] < reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JLE_IMM:
            if (reg[inst.dst] <= (uint32_t)inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JLE_REG:
            if (reg[inst.dst] <= reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSET_IMM:
            if (reg[inst.dst] & inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSET_REG:
            if (reg[inst.dst] & reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JNE_IMM:
            if (reg[inst.dst] != inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JNE_REG:
            if (reg[inst.dst] != reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSGT_IMM:
            if ((int64_t)reg[inst.dst] > inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSGT_REG:
            if ((int64_t)reg[inst.dst] > (int64_t)reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSGE_IMM:
            if ((int64_t)reg[inst.dst] >= inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSGE_REG:
            if ((int64_t)reg[inst.dst] >= (int64_t)reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSLT_IMM:
            if ((int64_t)reg[inst.dst] < inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSLT_REG:
            if ((int64_t)reg[inst.dst] < (int64_t)reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSLE_IMM:
            if ((int64_t)reg[inst.dst] <= inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSLE_REG:
            if ((int64_t)reg[inst.dst] <= (int64_t)reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_EXIT:
            return reg[0];
        case EBPF_OP_CALL:
            reg[0] = vm->ext_funcs[inst.imm](reg[1], reg[2], reg[3], reg[4], reg[5]);
            break;
        }
    }
}

static bool
validate(const struct ubpf_vm *vm, const struct ebpf_inst *insts, uint32_t num_insts, char **errmsg, uint32_t *num_load_store, int *rewrite_pcs)
{
    if (num_insts >= MAX_INSTS) {
        *errmsg = ubpf_error("too many instructions (max %u)", MAX_INSTS);
        return false;
    }

    /* Actually, having an exit at the end of instructions does not guarantee that it will finish... */
    /* Rather, check if one of the instructions is an EBPF_OP_EXIT */
    /*
    if (num_insts == 0 || insts[num_insts-1].opcode != EBPF_OP_EXIT) {
        *errmsg = ubpf_error("no exit at end of instructions");
        return false;
    }*/

    int exit_insts_index;
    for (exit_insts_index = 0; exit_insts_index < num_insts; exit_insts_index++) {
        if (insts[exit_insts_index].opcode == EBPF_OP_EXIT) {
            break;
        }
    }

    if (exit_insts_index >= num_insts) {
        *errmsg = ubpf_error("no exit in instructions");
        return false;
    }

    int i;
    for (i = 0; i < num_insts; i++) {
        struct ebpf_inst inst = insts[i];
        bool store = false;

        switch (inst.opcode) {
        case EBPF_OP_ADD_IMM:
        case EBPF_OP_ADD_REG:
        case EBPF_OP_SUB_IMM:
        case EBPF_OP_SUB_REG:
        case EBPF_OP_MUL_IMM:
        case EBPF_OP_MUL_REG:
        case EBPF_OP_DIV_REG:
        case EBPF_OP_OR_IMM:
        case EBPF_OP_OR_REG:
        case EBPF_OP_AND_IMM:
        case EBPF_OP_AND_REG:
        case EBPF_OP_LSH_IMM:
        case EBPF_OP_LSH_REG:
        case EBPF_OP_RSH_IMM:
        case EBPF_OP_RSH_REG:
        case EBPF_OP_NEG:
        case EBPF_OP_MOD_REG:
        case EBPF_OP_XOR_IMM:
        case EBPF_OP_XOR_REG:
        case EBPF_OP_MOV_IMM:
        case EBPF_OP_MOV_REG:
        case EBPF_OP_ARSH_IMM:
        case EBPF_OP_ARSH_REG:
            break;

        case EBPF_OP_LE:
        case EBPF_OP_BE:
            if (inst.imm != 16 && inst.imm != 32 && inst.imm != 64) {
                *errmsg = ubpf_error("invalid endian immediate at PC %d", i);
                return false;
            }
            break;

        case EBPF_OP_ADD64_IMM:
        case EBPF_OP_ADD64_REG:
        case EBPF_OP_SUB64_IMM:
        case EBPF_OP_SUB64_REG:
        case EBPF_OP_MUL64_IMM:
        case EBPF_OP_MUL64_REG:
        case EBPF_OP_DIV64_REG:
        case EBPF_OP_OR64_IMM:
        case EBPF_OP_OR64_REG:
        case EBPF_OP_AND64_IMM:
        case EBPF_OP_AND64_REG:
        case EBPF_OP_LSH64_IMM:
        case EBPF_OP_LSH64_REG:
        case EBPF_OP_RSH64_IMM:
        case EBPF_OP_RSH64_REG:
        case EBPF_OP_NEG64:
        case EBPF_OP_MOD64_REG:
        case EBPF_OP_XOR64_IMM:
        case EBPF_OP_XOR64_REG:
        case EBPF_OP_MOV64_IMM:
        case EBPF_OP_MOV64_REG:
        case EBPF_OP_ARSH64_IMM:
        case EBPF_OP_ARSH64_REG:
            break;

        case EBPF_OP_LDXW:
        case EBPF_OP_LDXH:
        case EBPF_OP_LDXB:
        case EBPF_OP_LDXDW:
            if (inst.src != 10) {
                if (*num_load_store >= MAX_LOAD_STORE) {
                    *errmsg = ubpf_error("Too many load and store, currently limited to %d", MAX_LOAD_STORE);
                    return false;
                }
                rewrite_pcs[*num_load_store] = i;
                *num_load_store += 1;
            } else {
                if (inst.offset > 0 || inst.offset < - STACK_SIZE) {
                    *errmsg = ubpf_error("Load crushes stack with offset %d at PC %d",  inst.offset, i);
                    return false;
                }
            }
            break;

        case EBPF_OP_STW:
        case EBPF_OP_STH:
        case EBPF_OP_STB:
        case EBPF_OP_STDW:
        case EBPF_OP_STXW:
        case EBPF_OP_STXH:
        case EBPF_OP_STXB:
        case EBPF_OP_STXDW:
            if (inst.dst != 10) {
                if (*num_load_store >= MAX_LOAD_STORE) {
                    *errmsg = ubpf_error("Too many load and store, currently limited to %d", MAX_LOAD_STORE);
                    return false;
                }
                rewrite_pcs[*num_load_store] = i;
                *num_load_store += 1;
            } else {
                if (inst.offset > 0 || inst.offset < - STACK_SIZE) {
                    *errmsg = ubpf_error("Store crushes stack with offset %d at PC %d",  inst.offset, i);
                    return false;
                }
            }
            store = true;
            break;

        case EBPF_OP_LDDW:
            if (i + 1 >= num_insts || insts[i+1].opcode != 0) {
                *errmsg = ubpf_error("incomplete lddw at PC %d", i);
                return false;
            }
            i++; /* Skip next instruction */
            break;

        case EBPF_OP_JA:
        case EBPF_OP_JEQ_REG:
        case EBPF_OP_JEQ_IMM:
        case EBPF_OP_JGT_REG:
        case EBPF_OP_JGT_IMM:
        case EBPF_OP_JGE_REG:
        case EBPF_OP_JGE_IMM:
        case EBPF_OP_JLT_REG:
        case EBPF_OP_JLT_IMM:
        case EBPF_OP_JLE_REG:
        case EBPF_OP_JLE_IMM:
        case EBPF_OP_JSET_REG:
        case EBPF_OP_JSET_IMM:
        case EBPF_OP_JNE_REG:
        case EBPF_OP_JNE_IMM:
        case EBPF_OP_JSGT_IMM:
        case EBPF_OP_JSGT_REG:
        case EBPF_OP_JSGE_IMM:
        case EBPF_OP_JSGE_REG:
        case EBPF_OP_JSLT_IMM:
        case EBPF_OP_JSLT_REG:
        case EBPF_OP_JSLE_IMM:
        case EBPF_OP_JSLE_REG:
            if (inst.offset == -1) {
                *errmsg = ubpf_error("infinite loop at PC %d", i);
                return false;
            }
            int new_pc = i + 1 + inst.offset;
            if (new_pc < 0 || new_pc >= num_insts) {
                *errmsg = ubpf_error("jump out of bounds at PC %d", i);
                return false;
            } else if (insts[new_pc].opcode == 0) {
                *errmsg = ubpf_error("jump to middle of lddw at PC %d", i);
                return false;
            }
            break;

        case EBPF_OP_CALL:
            if (inst.imm < 0 || inst.imm >= MAX_EXT_FUNCS) {
                *errmsg = ubpf_error("invalid call immediate at PC %d", i);
                return false;
            }
            if (!vm->ext_funcs[inst.imm]) {
                *errmsg = ubpf_error("call to nonexistent function %u at PC %d", inst.imm, i);
                return false;
            }
            break;

        case EBPF_OP_EXIT:
            break;

        case EBPF_OP_DIV_IMM:
        case EBPF_OP_MOD_IMM:
        case EBPF_OP_DIV64_IMM:
        case EBPF_OP_MOD64_IMM:
            if (inst.imm == 0) {
                *errmsg = ubpf_error("division by zero at PC %d", i);
                return false;
            }
            break;

        default:
            *errmsg = ubpf_error("unknown opcode 0x%02x at PC %d", inst.opcode, i);
            return false;
        }

        if (inst.src > 10) {
            *errmsg = ubpf_error("invalid source register at PC %d", i);
            return false;
        }

        if (inst.dst > 9 && !(store && inst.dst == 10)) {
            *errmsg = ubpf_error("invalid destination register at PC %d", i);
            return false;
        }
    }

    return true;
}

/**
 * Rewrite the code loaded in vm->insts
 * @param vm
 * @param insts old buffer containing eBPF instructions
 * @param num_inst total number of instructions in "insts"
 * @param errmsg not used
 * @param ctx_id eBPF context for this vm
 * @return
 */
static bool rewrite_with_ctx(struct ubpf_vm *vm, const struct ebpf_inst *insts, uint32_t num_inst, char **errmsg, uint64_t ctx_id) {

    int pc = 0;
    uint32_t i;

    struct ebpf_inst inst;
    uint32_t num_call = 0;
    int rewrite_pcs[MAX_CALL];

    uint16_t new_offset;
    uint32_t new_num_insts;

    /* 1st pass : locate EBPF_OP_CALL */
    for(i = 0; i < num_inst; i++) {
        inst = insts[i];

        switch (inst.opcode) {
            case EBPF_OP_CALL:
                rewrite_pcs[num_call] = i;
                num_call++;

                if(num_call >= MAX_CALL) {
                    *errmsg = "Too many calls (EBPF_OP_CALL)";
                    return false;
                }
                break;
            default:
                break;
        }


    }

    new_num_insts = vm->num_insts + (num_call * ADDED_CTX_CALL);

    vm->insts = malloc(new_num_insts * 8);
    if(!vm->num_insts) {
        *errmsg = "Cannot allocate space for rewritten eBPF instructions";
        return false;
    }
    vm->num_insts = new_num_insts;

    /* 2nd pass : rewrite ebpf assembly accordingly */
    for(i = 0; i < num_inst; i++) {

        inst = insts[i];

        switch (inst.opcode) {
            case EBPF_OP_CALL:
                /* 12 extra eBPF instructions to pass ctx for helper functions */

                /* copy R5 to R13 (tmp register) */
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_MOV64_REG, .dst = 12, .src = 5, .offset = 0, .imm = 0};
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_MOV64_REG, .dst = 5, .src = 4, .offset = 0, .imm = 0};
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_MOV64_REG, .dst = 4, .src = 3, .offset = 0, .imm = 0};
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_MOV64_REG, .dst = 3, .src = 2, .offset = 0, .imm = 0};
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_MOV64_REG, .dst = 2, .src = 1, .offset = 0, .imm = 0};
                /* copy ctx_id to R1 */
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_LDDW, .dst = 1, .src = 0, .offset = 0, .imm = ctx_id & UINT32_MAX};
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = 0, .dst = 0, .src = 0, .offset = 0, .imm = ctx_id >> 32u};

                /* call instruction */
                vm->insts[pc++] = inst;

                /* call has been executed, revert back registers */
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_MOV64_REG, .dst = 1, .src = 2, .offset = 0, .imm = 0};
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_MOV64_REG, .dst = 2, .src = 3, .offset = 0, .imm = 0};
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_MOV64_REG, .dst = 3, .src = 4, .offset = 0, .imm = 0};
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_MOV64_REG, .dst = 4, .src = 5, .offset = 0, .imm = 0};
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_MOV64_REG, .dst = 5, .src = 12, .offset = 0, .imm = 0};
                break;

            case EBPF_OP_JA:
            case EBPF_OP_JEQ_REG:
            case EBPF_OP_JEQ_IMM:
            case EBPF_OP_JGT_REG:
            case EBPF_OP_JGT_IMM:
            case EBPF_OP_JGE_REG:
            case EBPF_OP_JGE_IMM:
            case EBPF_OP_JLT_REG:
            case EBPF_OP_JLT_IMM:
            case EBPF_OP_JLE_REG:
            case EBPF_OP_JLE_IMM:
            case EBPF_OP_JSET_REG:
            case EBPF_OP_JSET_IMM:
            case EBPF_OP_JNE_REG:
            case EBPF_OP_JNE_IMM:
            case EBPF_OP_JSGT_IMM:
            case EBPF_OP_JSGT_REG:
            case EBPF_OP_JSGE_IMM:
            case EBPF_OP_JSGE_REG:
            case EBPF_OP_JSLT_IMM:
            case EBPF_OP_JSLT_REG:
            case EBPF_OP_JSLE_IMM:
            case EBPF_OP_JSLE_REG:
                /* rewriting jumps according to the number of new instructions added */

                new_offset = inst.offset;
                if (inst.offset > 0) {
                    for (int j = 0; j < num_call && rewrite_pcs[j] < i + 1 + inst.offset; j++) {
                        /* We should jump all loads/stores in range [ next_pc ; next_pc + offset [ */
                        if (rewrite_pcs[j] >= i + 1 && rewrite_pcs[j] < i + 1 + inst.offset) {
                            new_offset += ADDED_CTX_CALL;
                        }
                    }
                }
                else if (inst.offset < 0) {
                    for (int j = 0; j < num_call && rewrite_pcs[j] < i + 1; j++) {
                        /* We should jump all loads/stores in range [ next_pc + offset ; next_pc [ */
                        /* Notice that here, offset is negative */
                        if (rewrite_pcs[j] >= i + 1 + inst.offset && rewrite_pcs[j] < i + 1) {
                            new_offset -= ADDED_CTX_CALL;
                        }
                    }
                }
                /* And put the jump with the new offset */
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = inst.opcode, .dst = inst.dst, .src = inst.src, .offset = new_offset, .imm = inst.imm};
                break;
            default:
                vm->insts[pc++] = inst;
        }

    }
    return true;
}

static bool
rewrite_with_memchecks(struct ubpf_vm *vm, const struct ebpf_inst *insts, uint32_t num_insts, char **errmsg, uint64_t memory_ptr, uint32_t memory_size, uint32_t num_load_store, int *rewrite_pcs)
{
    int pc = 0;
    uint64_t memory_ptr_top = memory_ptr + (uint64_t) memory_size;

    int i;
    int16_t new_offset;
    for (i = 0; i < num_insts; i++) {
        struct ebpf_inst inst = insts[i];

        switch (inst.opcode) {
        case EBPF_OP_LDXW:
        case EBPF_OP_LDXH:
        case EBPF_OP_LDXB:
        case EBPF_OP_LDXDW:
            if (inst.src != 10) {
                /* Adding 22 instructions checking bounds */
                /* Step 1: check that the accessed pointer is >= memory_ptr */
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_LDDW, .dst = 11, .src = 0, .offset = 0, .imm = memory_ptr_top & UINT32_MAX};
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = 0, .dst = 0, .src = 0, .offset = 0, .imm = memory_ptr_top >> 32};
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_SUB64_REG, .dst = 11, .src = inst.src, .offset = 0, .imm = 0};
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_SUB64_IMM, .dst = 11, .src = 0, .offset = 0, .imm = (int32_t) inst.offset};
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_JSGE_IMM, .dst = 11, .src = 0, .offset = 1, .imm = 0};
                /* We failed the test, jump to the error */
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_JA, .dst = 0, .src = 0, .offset = 1, .imm = 0};
                /* Step 2: check that the accessed pointer - memory_size <= memory_ptr */
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_JLE_IMM, .dst = 11, .src = 0, .offset = 15, .imm = memory_size};
                /* We failed one of the tests for the store, but maybe we try to access the stack from another register than R10? */
                /* Step 3: check that the accessed pointer is <= stack_ptr */
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_MOV64_REG, .dst = 11, .src = inst.src, .offset = 0, .imm = 0};
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_ADD64_IMM, .dst = 11, .src = 0, .offset = 0, .imm = (int32_t) inst.offset};
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_JLE_REG, .dst = 11, .src = 10, .offset = 1, .imm = 0};
                /* We failed the test, jump to the error */
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_JA, .dst = 0, .src = 0, .offset = 2, .imm = 0};
                /* Step 4: check that the accessed pointer + stack_size >= stack_ptr */
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_ADD64_IMM, .dst = 11, .src = 0, .offset = 0, .imm = STACK_SIZE};
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_JGE_REG, .dst = 11, .src = 10, .offset = 9, .imm = 0};
                /* We failed one of the tests, log the error and exits */
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_MOV64_REG, .dst = 1, .src = inst.src, .offset = 0, .imm = 0};
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_ADD64_IMM, .dst = 1, .src = 0, .offset = 0, .imm = (int32_t) inst.offset};
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_LDDW, .dst = 2, .src = 0, .offset = 0, .imm = memory_ptr & UINT32_MAX};
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = 0, .dst = 0, .src = 0, .offset = 0, .imm = memory_ptr >> 32};
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_MOV64_REG, .dst = 3, .src = 10, .offset = 0, .imm = 0};
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_CALL, .dst = 0, .src = 0, .offset = 0, .imm = OOB_CALL};
                // EXIT CODE UINT64_MAX
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_LDDW, .dst = 0, .src = 0, .offset = 0, .imm = UINT32_MAX};
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = 0, .dst = 0, .src = 0, .offset = 0, .imm = UINT32_MAX};
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_EXIT, .dst = 0, .src = 0, .offset = 0, .imm = 0};
            }
            /* And eventually add the load */
            vm->insts[pc++] = inst;
            break;

        case EBPF_OP_STW:
        case EBPF_OP_STH:
        case EBPF_OP_STB:
        case EBPF_OP_STDW:
        case EBPF_OP_STXW:
        case EBPF_OP_STXH:
        case EBPF_OP_STXB:
        case EBPF_OP_STXDW:
            if (inst.dst != 10) {
                /* Adding 22 instructions checking bounds */
                /* Step 1: check that the accessed pointer is >= memory_ptr */
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_LDDW, .dst = 11, .src = 0, .offset = 0, .imm = memory_ptr_top & UINT32_MAX};
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = 0, .dst = 0, .src = 0, .offset = 0, .imm = memory_ptr_top >> 32};
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_SUB64_REG, .dst = 11, .src = inst.dst, .offset = 0, .imm = 0};
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_SUB64_IMM, .dst = 11, .src = 0, .offset = 0, .imm = (int32_t) inst.offset};
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_JSGE_IMM, .dst = 11, .src = 0, .offset = 1, .imm = 0};
                /* We failed the test, jump to the error */
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_JA, .dst = 0, .src = 0, .offset = 1, .imm = 0};
                /* Step 2: check that the accessed pointer - memory_size <= memory_ptr */
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_JLE_IMM, .dst = 11, .src = 0, .offset = 15, .imm = memory_size};
                /* We failed one of the tests for the store, but maybe we try to access the stack from another register than R10? */
                /* Step 3: check that the accessed pointer is <= stack_ptr */
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_MOV64_REG, .dst = 11, .src = inst.dst, .offset = 0, .imm = 0};
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_ADD64_IMM, .dst = 11, .src = 0, .offset = 0, .imm = (int32_t) inst.offset};
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_JLE_REG, .dst = 11, .src = 10, .offset = 1, .imm = 0};
                /* We failed the test, jump to the error */
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_JA, .dst = 0, .src = 0, .offset = 2, .imm = 0};
                /* Step 4: check that the accessed pointer + stack_size >= stack_ptr */
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_ADD64_IMM, .dst = 11, .src = 0, .offset = 0, .imm = STACK_SIZE};
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_JGE_REG, .dst = 11, .src = 10, .offset = 9, .imm = 0};
                /* We failed one of the tests, log the error and exits */
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_MOV64_REG, .dst = 1, .src = inst.dst, .offset = 0, .imm = 0};
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_ADD64_IMM, .dst = 1, .src = 0, .offset = 0, .imm = (int32_t) inst.offset};
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_LDDW, .dst = 2, .src = 0, .offset = 0, .imm = memory_ptr & UINT32_MAX};
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = 0, .dst = 0, .src = 0, .offset = 0, .imm = memory_ptr >> 32};
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_MOV64_REG, .dst = 3, .src = 10, .offset = 0, .imm = 0};
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_CALL, .dst = 0, .src = 0, .offset = 0, .imm = OOB_CALL};
                // EXIT CODE UINT64_MAX
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_LDDW, .dst = 0, .src = 0, .offset = 0, .imm = UINT32_MAX};
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = 0, .dst = 0, .src = 0, .offset = 0, .imm = UINT32_MAX};
                vm->insts[pc++] = (struct ebpf_inst) {.opcode = EBPF_OP_EXIT, .dst = 0, .src = 0, .offset = 0, .imm = 0};
            }
            /* And eventually add it */
            vm->insts[pc++] = inst;
            break;

        /* We also need to handle jumps; what happen if a store or a load should have been jumped? */
        case EBPF_OP_JA:
        case EBPF_OP_JEQ_REG:
        case EBPF_OP_JEQ_IMM:
        case EBPF_OP_JGT_REG:
        case EBPF_OP_JGT_IMM:
        case EBPF_OP_JGE_REG:
        case EBPF_OP_JGE_IMM:
        case EBPF_OP_JLT_REG:
        case EBPF_OP_JLT_IMM:
        case EBPF_OP_JLE_REG:
        case EBPF_OP_JLE_IMM:
        case EBPF_OP_JSET_REG:
        case EBPF_OP_JSET_IMM:
        case EBPF_OP_JNE_REG:
        case EBPF_OP_JNE_IMM:
        case EBPF_OP_JSGT_IMM:
        case EBPF_OP_JSGT_REG:
        case EBPF_OP_JSGE_IMM:
        case EBPF_OP_JSGE_REG:
        case EBPF_OP_JSLT_IMM:
        case EBPF_OP_JSLT_REG:
        case EBPF_OP_JSLE_IMM:
        case EBPF_OP_JSLE_REG:
            new_offset = inst.offset;
            if (inst.offset > 0) {
                for (int j = 0; j < num_load_store && rewrite_pcs[j] < i + 1 + inst.offset; j++) {
                    /* We should jump all loads/stores in range [ next_pc ; next_pc + offset [ */
                    if (rewrite_pcs[j] >= i + 1 && rewrite_pcs[j] < i + 1 + inst.offset) {
                        new_offset += ADDED_LOAD_STORE_INSTS;
                    }
                }
            }
            else if (inst.offset < 0) {
                for (int j = 0; j < num_load_store && rewrite_pcs[j] < i + 1; j++) {
                    /* We should jump all loads/stores in range [ next_pc + offset ; next_pc [ */
                    /* Notice that here, offset is negative */
                    if (rewrite_pcs[j] >= i + 1 + inst.offset && rewrite_pcs[j] < i + 1) {
                        new_offset -= ADDED_LOAD_STORE_INSTS;
                    }
                }
            }
            /* And put the jump with the new offset */
            vm->insts[pc++] = (struct ebpf_inst) {.opcode = inst.opcode, .dst = inst.dst, .src = inst.src, .offset = new_offset, .imm = inst.imm};
            break;

        default:
            /* Simply copy the instruction */
            vm->insts[pc++] = inst;
        }
    }
    return true;
}

static bool
bounds_check(struct ubpf_vm *vm, void *addr, int size, const char *type, uint16_t cur_pc, void *mem, size_t mem_len,
             void *stack) {

    /*if (mem && (addr >= mem && (addr + size) <= (mem + mem_len))) {
        // Context access
        fprintf(stderr, "context access ?\n");
        return true;
    } else */ // disallowing this for the moment
    if (vm->extra_mem_size != 0 && // compare only if this VM contains extra memory
               (addr >= vm->extra_mem_start && (addr + size) < (vm->extra_mem_start + vm->extra_mem_size))
            ) {
        /* Extra memory access */
        return true;
    } else if (addr >= stack && (addr + size) <= (stack + STACK_SIZE)) {
        /* Stack access */
        return true;
    } else {
        snprintf(vm->error_msg, MAX_ERROR_MSG,
                 "uBPF error: out of bounds memory %s at PC %u, addr %p, size %d\nmem %p/%zd stack %p/%d\n", type,
                 cur_pc, addr, size, mem, mem_len, stack, STACK_SIZE);
        fprintf(stderr, "%s", vm->error_msg);
        return false;
    }
}

char *
ubpf_error(const char *fmt, ...)
{
    char *msg;
    va_list ap;
    va_start(ap, fmt);
    if (vasprintf(&msg, fmt, ap) < 0) {
        msg = NULL;
    }
    va_end(ap);
    return msg;
}
