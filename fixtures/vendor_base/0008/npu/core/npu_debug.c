/*
 * npu_debug.c - NPU debugfs surface
 * NOTE: this file is stored with CRLF line endings on purpose.
 */

#include "npu_types.h"
#include <linux/debugfs.h>

static struct dentry *npu_debug_root;

static ssize_t npu_debug_regs_read(struct file *f, char __user *ubuf,
                                   size_t count, loff_t *ppos)
{
    struct npu_device *dev = f->private_data;
    char buf[256];
    int n;

    n = scnprintf(buf, sizeof(buf), "state=%u qos=%u\n",
                  dev->power_state, dev->qos.level);

    return simple_read_from_buffer(ubuf, count, ppos, buf, n);
}

static ssize_t npu_debug_raw_poke(struct file *f, const char __user *ubuf,
                                  size_t count, loff_t *ppos)
{
    struct npu_device *dev = f->private_data;
    u32 off, val;

    if (sscanf_from_user(ubuf, count, "%x %x", &off, &val) != 2)
        return -EINVAL;

    npu_hal_write(dev, off, val);
    return count;
}

void npu_debug_init(struct npu_device *dev)
{
    npu_debug_root = debugfs_create_dir("npu", NULL);

    debugfs_create_file("regs", 0444, npu_debug_root, dev,
                        &npu_debug_regs_fops);
    debugfs_create_file("poke", 0222, npu_debug_root, dev,
                        &npu_debug_poke_fops);
}
