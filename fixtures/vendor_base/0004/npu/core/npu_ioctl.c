/*
 * npu_ioctl.c - NPU character device ioctl surface
 */

#include "npu_types.h"
#include <linux/uaccess.h>

#define NPU_IOCTL_SUBMIT   _IOW('N', 0x01, struct npu_job_req)
#define NPU_IOCTL_QUERY    _IOR('N', 0x02, struct npu_query_rsp)

long npu_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    struct npu_device *dev = filp->private_data;
    struct npu_job_req req;

    switch (cmd) {
    case NPU_IOCTL_SUBMIT:
        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;

        return npu_sched_submit(dev, req.job);

    case NPU_IOCTL_QUERY:
        return npu_query_state(dev, (void __user *)arg);

    default:
        return -ENOTTY;
    }
}
