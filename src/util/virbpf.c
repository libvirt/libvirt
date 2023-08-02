/*
 * virbpf.c: methods for eBPF
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
#include <config.h>

#include "virlog.h"
#include "virbpf.h"

VIR_LOG_INIT("util.bpf");

#define VIR_FROM_THIS VIR_FROM_BPF

#ifdef __linux__
# include <sys/syscall.h>
# include <unistd.h>


int
virBPFCreateMap(unsigned int mapType,
                unsigned int keySize,
                unsigned int valSize,
                unsigned int maxEntries)
{
    union bpf_attr attr = { 0 };

    attr.map_type = mapType;
    attr.key_size = keySize;
    attr.value_size = valSize;
    attr.max_entries = maxEntries;

    return syscall(SYS_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
}


# define LOG_BUF_SIZE (256 * 1024)

int
virBPFLoadProg(struct bpf_insn *insns,
               int progType,
               unsigned int insnCnt)
{
    g_autofree char *logbuf = NULL;
    int progfd = -1;
    union bpf_attr attr = { 0 };

    logbuf = g_new0(char, LOG_BUF_SIZE);

    attr.prog_type = progType;
    attr.insn_cnt = insnCnt;
    attr.insns = (uintptr_t)insns;
    attr.license = (uintptr_t)"GPL";
    attr.log_buf = (uintptr_t)logbuf;
    attr.log_size = LOG_BUF_SIZE;
    attr.log_level = 1;

    progfd = syscall(SYS_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));

    if (progfd < 0)
        VIR_DEBUG("%s", logbuf);

    return progfd;
}


int
virBPFAttachProg(int progfd,
                 int targetfd,
                 int attachType)
{
    union bpf_attr attr = { 0 };

    attr.target_fd = targetfd;
    attr.attach_bpf_fd = progfd;
    attr.attach_type = attachType;

    return syscall(SYS_bpf, BPF_PROG_ATTACH, &attr, sizeof(attr));
}


int
virBPFDetachProg(int progfd,
                 int targetfd,
                 int attachType)
{
    union bpf_attr attr = { 0 };

    attr.target_fd = targetfd;
    attr.attach_bpf_fd = progfd;
    attr.attach_type = attachType;

    return syscall(SYS_bpf, BPF_PROG_DETACH, &attr, sizeof(attr));
}


int
virBPFQueryProg(int targetfd,
                unsigned int maxprogids,
                int attachType,
                unsigned int *progcnt,
                void *progids)
{
    union bpf_attr attr = { 0 };
    int rc;

    attr.query.target_fd = targetfd;
    attr.query.attach_type = attachType;
    attr.query.prog_cnt = maxprogids;
    attr.query.prog_ids = (uintptr_t)progids;

    rc = syscall(SYS_bpf, BPF_PROG_QUERY, &attr, sizeof(attr));

    if (rc >= 0)
        *progcnt = attr.query.prog_cnt;

    return rc;
}


int
virBPFGetProg(unsigned int id)
{
    union bpf_attr attr = { 0 };

    attr.prog_id = id;

    return syscall(SYS_bpf, BPF_PROG_GET_FD_BY_ID, &attr, sizeof(attr));
}


int
virBPFGetProgInfo(int progfd,
                  struct bpf_prog_info *info,
                  unsigned int **mapIDs)
{
    union bpf_attr attr = { 0 };
    int rc;

    attr.info.bpf_fd = progfd;
    attr.info.info_len = sizeof(struct bpf_prog_info);
    attr.info.info = (uintptr_t)info;

    rc = syscall(SYS_bpf, BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));
    if (rc < 0)
        return rc;

    if (mapIDs && info->nr_map_ids > 0) {
        unsigned int maplen = info->nr_map_ids;
        g_autofree unsigned int *retmapIDs = NULL;

        retmapIDs = g_new0(unsigned int, maplen);

        memset(info, 0, sizeof(struct bpf_prog_info));
        info->nr_map_ids = maplen;
        info->map_ids = (uintptr_t)retmapIDs;

        memset(&attr, 0, sizeof(attr));
        attr.info.bpf_fd = progfd;
        attr.info.info_len = sizeof(struct bpf_prog_info);
        attr.info.info = (uintptr_t)info;

        rc = syscall(SYS_bpf, BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));
        if (rc < 0)
            return rc;

        *mapIDs = g_steal_pointer(&retmapIDs);
    }

    return rc;
}


int
virBPFGetMap(unsigned int id)
{
    union bpf_attr attr = { 0 };

    attr.map_id = id;

    return syscall(SYS_bpf, BPF_MAP_GET_FD_BY_ID, &attr, sizeof(attr));
}


int
virBPFGetMapInfo(int mapfd,
                 struct bpf_map_info *info)
{
    union bpf_attr attr = { 0 };

    attr.info.bpf_fd = mapfd;
    attr.info.info_len = sizeof(struct bpf_map_info);
    attr.info.info = (uintptr_t)info;

    return syscall(SYS_bpf, BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));
}


int
virBPFLookupElem(int mapfd,
                 void *key,
                 void *val)
{
    union bpf_attr attr = { 0 };

    attr.map_fd = mapfd;
    attr.key = (uintptr_t)key;
    attr.value = (uintptr_t)val;

    return syscall(SYS_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}


int
virBPFGetNextElem(int mapfd,
                  void *key,
                  void *nextKey)
{
    union bpf_attr attr = { 0 };

    attr.map_fd = mapfd;
    attr.key = (uintptr_t)key;
    attr.next_key = (uintptr_t)nextKey;

    return syscall(SYS_bpf, BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr));
}


int
virBPFUpdateElem(int mapfd,
                 void *key,
                 void *val)
{
    union bpf_attr attr = { 0 };

    attr.map_fd = mapfd;
    attr.key = (uintptr_t)key;
    attr.value = (uintptr_t)val;

    return syscall(SYS_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}


int
virBPFDeleteElem(int mapfd,
                 void *key)
{
    union bpf_attr attr = { 0 };

    attr.map_fd = mapfd;
    attr.key = (uintptr_t)key;

    return syscall(SYS_bpf, BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}


#else /* ! __linux__ */


int
virBPFCreateMap(unsigned int mapType G_GNUC_UNUSED,
                unsigned int keySize G_GNUC_UNUSED,
                unsigned int valSize G_GNUC_UNUSED,
                unsigned int maxEntries G_GNUC_UNUSED)
{
    errno = ENOSYS;
    return -1;
}


int
virBPFLoadProg(struct bpf_insn *insns G_GNUC_UNUSED,
               int progType G_GNUC_UNUSED,
               unsigned int insnCnt G_GNUC_UNUSED)
{
    errno = ENOSYS;
    return -1;
}


int
virBPFAttachProg(int progfd G_GNUC_UNUSED,
                 int targetfd G_GNUC_UNUSED,
                 int attachType G_GNUC_UNUSED)
{
    errno = ENOSYS;
    return -1;
}


int
virBPFDetachProg(int progfd G_GNUC_UNUSED,
                 int targetfd G_GNUC_UNUSED,
                 int attachType G_GNUC_UNUSED)
{
    errno = ENOSYS;
    return -1;
}


int
virBPFQueryProg(int targetfd G_GNUC_UNUSED,
                unsigned int maxprogids G_GNUC_UNUSED,
                int attachType G_GNUC_UNUSED,
                unsigned int *progcnt G_GNUC_UNUSED,
                void *progids G_GNUC_UNUSED)
{
    errno = ENOSYS;
    return -1;
}


int
virBPFGetProg(unsigned int id G_GNUC_UNUSED)
{
    errno = ENOSYS;
    return -1;
}


int
virBPFGetProgInfo(int progfd G_GNUC_UNUSED,
                  struct bpf_prog_info *info G_GNUC_UNUSED,
                  unsigned int **mapIDs G_GNUC_UNUSED)
{
    errno = ENOSYS;
    return -1;
}


int
virBPFGetMap(unsigned int id G_GNUC_UNUSED)
{
    errno = ENOSYS;
    return -1;
}


int
virBPFGetMapInfo(int mapfd G_GNUC_UNUSED,
                 struct bpf_map_info *info G_GNUC_UNUSED)
{
    errno = ENOSYS;
    return -1;
}


int
virBPFLookupElem(int mapfd G_GNUC_UNUSED,
                 void *key G_GNUC_UNUSED,
                 void *val G_GNUC_UNUSED)
{
    errno = ENOSYS;
    return -1;
}


int
virBPFGetNextElem(int mapfd G_GNUC_UNUSED,
                  void *key G_GNUC_UNUSED,
                  void *nextKey G_GNUC_UNUSED)
{
    errno = ENOSYS;
    return -1;
}


int
virBPFUpdateElem(int mapfd G_GNUC_UNUSED,
                 void *key G_GNUC_UNUSED,
                 void *val G_GNUC_UNUSED)
{
    errno = ENOSYS;
    return -1;
}


int
virBPFDeleteElem(int mapfd G_GNUC_UNUSED,
                 void *key G_GNUC_UNUSED)
{
    errno = ENOSYS;
    return -1;
}
#endif /* !__linux__ */
