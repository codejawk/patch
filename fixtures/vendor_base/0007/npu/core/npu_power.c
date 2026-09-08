/*
 * npu_power.c - NPU power domain control
 */

#include "npu_types.h"
#include <linux/pm_runtime.h>

int npu_power_on(struct npu_device *dev)
{
    int ret;

    ret = clk_prepare_enable(dev->core_clk);
    if (ret)
        return ret;

    ret = regulator_enable(dev->vdd);
    if (ret) {
        clk_disable_unprepare(dev->core_clk);
        return ret;
    }

    dev->power_state = NPU_POWER_ON;
    return 0;
}

int npu_power_off(struct npu_device *dev)
{
    regulator_disable(dev->vdd);
    clk_disable_unprepare(dev->core_clk);
    dev->power_state = NPU_POWER_OFF;
    return 0;
}
