/*
 * npu_mem_map.c - NPU IOVA mapping helpers
 * (vendor baseline calls this file npu/mem/npu_mem.c)
 */

#include "npu_types.h"
#include <linux/iommu.h>

#define NPU_IOVA_BASE   0x80000000UL
#define NPU_IOVA_SIZE   0x40000000UL

int npu_map_user_range(struct npu_device *dev,
                       unsigned long uaddr,
                       size_t len,
                       dma_addr_t *out_iova)
{
    dma_addr_t iova;
    int ret;

    iova = npu_iova_alloc(dev, len);
    if (!iova)
        return -ENOMEM;

    ret = iommu_map(dev->domain, iova, uaddr, len, IOMMU_READ | IOMMU_WRITE);
    if (ret) {
        npu_iova_free(dev, iova, len);
        return ret;
    }

    *out_iova = iova;
    return 0;
}
