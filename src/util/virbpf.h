/*
 * virbpf.h: methods for eBPF
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#pragma once

#ifdef __linux__

# include <linux/bpf.h>

/* ALU ops on registers, bpf_add|sub|...: dst_reg += src_reg */

# define VIR_BPF_ALU64_REG(op, dst, src) \
    ((struct bpf_insn) { \
     .code = BPF_ALU64 | BPF_OP(op) | BPF_X, \
     .dst_reg = dst, \
     .src_reg = src, \
     .off = 0, \
     .imm = 0, \
     })

/* ALU ops on immediates, bpf_add|sub|...: dst_reg += imm32 */

# define VIR_BPF_ALU64_IMM(op, dst, immval) \
    ((struct bpf_insn) { \
     .code = BPF_ALU64 | BPF_OP(op) | BPF_K, \
     .dst_reg = dst, \
     .src_reg = 0, \
     .off = 0, \
     .imm = immval, \
     })

/* mov of registers, dst_reg = src_reg */

# define VIR_BPF_MOV64_REG(dst, src) \
    ((struct bpf_insn) { \
     .code = BPF_ALU64 | BPF_MOV | BPF_X, \
     .dst_reg = dst, \
     .src_reg = src, \
     .off = 0, \
     .imm = 0, \
     })

/* mov of immediates, dst_reg = imm32 */

# define VIR_BPF_MOV64_IMM(dst, immval) \
    ((struct bpf_insn) { \
     .code = BPF_ALU64 | BPF_MOV | BPF_K, \
     .dst_reg = dst, \
     .src_reg = 0, \
     .off = 0, \
     .imm = immval, \
     })

/* helper to encode 16 byte instruction */

# define _VIR_BPF_LD_IMM64_RAW(dst, src, immval) \
    ((struct bpf_insn) { \
     .code = BPF_LD | BPF_DW | BPF_IMM, \
     .dst_reg = dst, \
     .src_reg = src, \
     .off = 0, \
     .imm = (uint32_t)immval, \
     }), \
    ((struct bpf_insn) { \
     .code = 0, \
     .dst_reg = 0, \
     .src_reg = 0, \
     .off = 0, \
     .imm = ((uint64_t)immval) >> 32, \
     })

/* encodes single 'load 64-bit immediate' insn, dst_reg = imm ll */

# define VIR_BPF_LD_IMM64(dst, imm) \
    _VIR_BPF_LD_IMM64_RAW(dst, 0, imm)

/* pseudo VIR_BPF_LD_IMM64 insn used to refer to process-local map_fd */

# define VIR_BPF_LD_MAP_FD(dst, mapfd) \
    _VIR_BPF_LD_IMM64_RAW(dst, 1, mapfd)

/* memory load, dst_reg = *(size *) (src_reg + off16) */

# define VIR_BPF_LDX_MEM(size, dst, src, offval) \
    ((struct bpf_insn) { \
     .code = BPF_LDX | BPF_SIZE(size) | BPF_MEM, \
     .dst_reg = dst, \
     .src_reg = src, \
     .off = offval, \
     .imm = 0, \
     })

/* memory store of registers, *(size *) (dst_reg + off16) = src_reg */

# define VIR_BPF_STX_MEM(size, dst, src, offval) \
    ((struct bpf_insn) { \
     .code = BPF_STX | BPF_SIZE(size) | BPF_MEM, \
     .dst_reg = dst, \
     .src_reg = src, \
     .off = offval, \
     .imm = 0, \
     })

/* memory store of immediates, *(size *) (dst_reg + off16) = imm32 */

# define VIR_BPF_ST_MEM(size, dst, immval, offval) \
    ((struct bpf_insn) { \
     .code = BPF_ST | BPF_SIZE(size) | BPF_MEM, \
     .dst_reg = dst, \
     .src_reg = 0, \
     .off = offval, \
     .imm = immval, \
     })

/* conditional jumps against registers, if (dst_reg 'op' src_reg) goto pc + off16 */

# define VIR_BPF_JMP_REG(op, dst, src, offval) \
    ((struct bpf_insn) { \
     .code = BPF_JMP | BPF_OP(op) | BPF_X, \
     .dst_reg = dst, \
     .src_reg = src, \
     .off = offval, \
     .imm = 0, \
     })

/* conditional jumps against immediates, if (dst_reg 'op' imm32) goto pc + off16 */

# define VIR_BPF_JMP_IMM(op, dst, immval, offval) \
    ((struct bpf_insn) { \
     .code = BPF_JMP | BPF_OP(op) | BPF_K, \
     .dst_reg = dst, \
     .src_reg = 0, \
     .off = offval, \
     .imm = immval, \
     })

/* call eBPF function, call imm32 */

# define VIR_BPF_CALL_INSN(func) \
    ((struct bpf_insn) { \
     .code = BPF_JMP | BPF_CALL, \
     .dst_reg = 0, \
     .src_reg = 0, \
     .off = 0, \
     .imm = func, \
     })

/* program exit */

# define VIR_BPF_EXIT_INSN() \
    ((struct bpf_insn) { \
     .code = BPF_JMP | BPF_EXIT, \
     .dst_reg = 0, \
     .src_reg = 0, \
     .off = 0, \
     .imm = 0, \
     })

#else /* ! __linux__ */

struct bpf_prog_info;
struct bpf_map_info;
struct bpf_insn;

# define VIR_BPF_ALU64_REG(op, dst, src)
# define VIR_BPF_ALU64_IMM(op, dst, immval)
# define VIR_BPF_MOV64_REG(dst, src)
# define VIR_BPF_MOV64_IMM(dst, immval)
# define VIR_BPF_LD_IMM64(dst, imm)
# define VIR_BPF_LD_MAP_FD(dst, mapfd)
# define VIR_BPF_LDX_MEM(size, dst, src, offval)
# define VIR_BPF_STX_MEM(size, dst, src, offval)
# define VIR_BPF_ST_MEM(size, dst, immval, offval)
# define VIR_BPF_JMP_REG(op, dst, src, offval)
# define VIR_BPF_JMP_IMM(op, dst, immval, offval)
# define VIR_BPF_CALL_INSN(func)
# define VIR_BPF_EXIT_INSN()

#endif /* ! __linux__ */

int
virBPFCreateMap(unsigned int mapType,
                unsigned int keySize,
                unsigned int valSize,
                unsigned int maxEntries);

int
virBPFGetMapInfo(int mapfd,
                 struct bpf_map_info *info);

int
virBPFLoadProg(struct bpf_insn *insns,
               int progType,
               unsigned int insnCnt);

int
virBPFAttachProg(int progfd,
                 int targetfd,
                 int attachType);

int
virBPFDetachProg(int progfd,
                 int targetfd,
                 int attachType);

int
virBPFQueryProg(int targetfd,
                unsigned int maxprogids,
                int attachType,
                unsigned int *progcnt,
                void *progids);

int
virBPFGetProg(unsigned int id);

int
virBPFGetProgInfo(int progfd,
                  struct bpf_prog_info *info,
                  unsigned int **mapIDs);

int
virBPFGetMap(unsigned int id);

int
virBPFLookupElem(int mapfd,
                 void *key,
                 void *val);

int
virBPFGetNextElem(int mapfd,
                  void *key,
                  void *nextKey);

int
virBPFUpdateElem(int mapfd,
                 void *key,
                 void *val);

int
virBPFDeleteElem(int mapfd,
                 void *key);
