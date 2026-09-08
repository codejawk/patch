/*
 * npu_power.c - NPU power domain control
 * Copyright (c) Samsung Electronics
 *
 * Samsung-local refactor: the single-regulator sequence was replaced by a
 * rail table so multi-rail chipsets share one code path. A vendor patch
 * written against the old sequence cannot apply here without a rebase.
 */

#include "npu_types.h"
#include <linux/pm_runtime.h>

static const struct npu_rail npu_rails[] = {
    { .name = "vdd_npu",  .required = true  },
    { .name = "vdd_sram", .required = true  },
    { .name = "vdd_mif",  .required = false },
};

int npu_power_on(struct npu_device *dev)
{
    int i, ret;

    ret = clk_prepare_enable(dev->core_clk);
    if (ret)
        return ret;

    for (i = 0; i < ARRAY_SIZE(npu_rails); i++) {
        ret = npu_rail_enable(dev, &npu_rails[i]);
        if (ret && npu_rails[i].required)
            goto err_rails;
    }

    dev->power_state = NPU_POWER_ON;
    return 0;

err_rails:
    while (--i >= 0)
        npu_rail_disable(dev, &npu_rails[i]);
    clk_disable_unprepare(dev->core_clk);
    return ret;
}

int npu_power_off(struct npu_device *dev)
{
    int i;

    for (i = ARRAY_SIZE(npu_rails) - 1; i >= 0; i--)
        npu_rail_disable(dev, &npu_rails[i]);

    clk_disable_unprepare(dev->core_clk);
    dev->power_state = NPU_POWER_OFF;
    return 0;
}
