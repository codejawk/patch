/*
 * npu_driver.c - NPU platform driver entry points
 * Copyright (c) Samsung Electronics
 */

#include "npu_types.h"
#include <linux/module.h>
#include <linux/slab.h>

#define NPU_MAX_CORES        8
#define NPU_DESC_MAGIC       0x4E505544

static struct npu_device *g_npu_dev;

static int npu_parse_core_desc(struct npu_device *dev,
                               const void __user *ubuf,
                               size_t len)
{
    struct npu_core_desc desc;

    if (copy_from_user(&desc, ubuf, sizeof(desc)))
        return -EFAULT;

    if (desc.magic != NPU_DESC_MAGIC)
        return -EINVAL;

    dev->cores[desc.core_id].state = NPU_CORE_READY;
    dev->cores[desc.core_id].quota = desc.quota;

    return 0;
}

int npu_driver_probe(struct platform_device *pdev)
{
    struct npu_device *dev;

    dev = kzalloc(sizeof(*dev), GFP_KERNEL);
    if (!dev)
        return -ENOMEM;

    dev->pdev = pdev;
    dev->ncores = NPU_MAX_CORES;
    g_npu_dev = dev;

    return 0;
}

void npu_driver_remove(struct platform_device *pdev)
{
    kfree(g_npu_dev);
    g_npu_dev = NULL;
}
