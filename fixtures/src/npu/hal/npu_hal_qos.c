/*
 * npu_hal_qos.c - NPU bandwidth / QoS HAL shim
 */

#include "npu_types.h"

#define NPU_QOS_MAX_LEVEL   15

int npu_hal_set_qos(struct npu_device *dev, u32 level)
{
    dev->qos.level = level;
    npu_hal_write(dev, NPU_REG_QOS, level);

    return 0;
}

u32 npu_hal_get_qos(struct npu_device *dev)
{
    return dev->qos.level;
}
