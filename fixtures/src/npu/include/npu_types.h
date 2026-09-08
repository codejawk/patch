/*
 * npu_types.h - shared NPU types
 */

#ifndef _NPU_TYPES_H_
#define _NPU_TYPES_H_

#include <linux/types.h>

enum npu_core_state {
    NPU_CORE_OFF = 0,
    NPU_CORE_READY,
    NPU_CORE_BUSY,
};

enum npu_power_state {
    NPU_POWER_OFF = 0,
    NPU_POWER_ON,
};

struct npu_core_desc {
    u32 magic;
    u32 core_id;
    u32 quota;
};

struct npu_fw_hdr {
    u32 magic;
    u32 payload_off;
    u32 payload_len;
};

struct npu_buffer {
    void       *cpu_addr;
    dma_addr_t  dma_addr;
    size_t      size;
    u32         flags;
};

#endif /* _NPU_TYPES_H_ */
