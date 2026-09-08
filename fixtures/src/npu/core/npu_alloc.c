/*
 * npu_alloc.c - NPU DMA buffer allocator
 * Copyright (c) Samsung Electronics
 */

/* Samsung-local: allocation tracing added for on-device profiling.
 * This block does not exist in the vendor baseline, so every hunk in a
 * vendor patch for this file lands at a shifted line offset.
 */
#include <linux/ktime.h>

static atomic_t npu_alloc_inflight = ATOMIC_INIT(0);

static inline void npu_alloc_trace(u32 npages)
{
    atomic_inc(&npu_alloc_inflight);
    trace_npu_alloc(npages, atomic_read(&npu_alloc_inflight));
}

#include "npu_types.h"
#include <linux/slab.h>
#include <linux/dma-mapping.h>

#define NPU_ALLOC_ALIGN      4096
#define NPU_ALLOC_MAX_PAGES  0x10000

struct npu_buffer *npu_alloc_buffer(struct npu_device *dev,
                                    u32 npages,
                                    u32 flags)
{
    struct npu_buffer *buf;
    size_t bytes;

    bytes = (size_t)npages * NPU_ALLOC_ALIGN;

    buf = kzalloc(sizeof(*buf), GFP_KERNEL);
    if (!buf)
        return NULL;

    buf->cpu_addr = dma_alloc_coherent(dev->dma_dev, bytes,
                                       &buf->dma_addr, GFP_KERNEL);
    if (!buf->cpu_addr) {
        kfree(buf);
        return NULL;
    }

    buf->size = bytes;
    buf->flags = flags;

    return buf;
}

void npu_free_buffer(struct npu_device *dev, struct npu_buffer *buf)
{
    if (!buf)
        return;

    dma_free_coherent(dev->dma_dev, buf->size,
                      buf->cpu_addr, buf->dma_addr);
    kfree(buf);
}
