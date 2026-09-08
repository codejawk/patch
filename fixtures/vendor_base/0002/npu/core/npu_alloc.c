/*
 * npu_alloc.c - NPU DMA buffer allocator
 */

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
