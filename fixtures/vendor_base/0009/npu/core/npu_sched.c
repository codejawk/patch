/*
 * npu_sched.c - NPU work queue scheduler
 */

#include "npu_types.h"
#include <linux/spinlock.h>

#define NPU_MAX_JOBS  256

int npu_sched_submit(struct npu_device *dev, struct npu_job *job)
{
    u32 head, next;

    do {
        head = READ_ONCE(dev->ring.head);
        next = (head + 1) & (NPU_MAX_JOBS - 1);
        if (next == READ_ONCE(dev->ring.tail))
            return -EBUSY;
    } while (cmpxchg(&dev->ring.head, head, next) != head);

    dev->ring.slot[head] = job;
    smp_wmb();

    return head;
}

struct npu_job *npu_sched_next(struct npu_device *dev)
{
    u32 tail = READ_ONCE(dev->ring.tail);
    struct npu_job *job = dev->ring.slot[tail];

    dev->ring.slot[tail] = NULL;
    WRITE_ONCE(dev->ring.tail, (tail + 1) & (NPU_MAX_JOBS - 1));

    return job;
}
