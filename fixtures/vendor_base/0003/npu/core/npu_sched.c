/*
 * npu_sched.c - NPU work queue scheduler
 */

#include "npu_types.h"
#include <linux/spinlock.h>

#define NPU_MAX_JOBS  256

static DEFINE_SPINLOCK(npu_sched_lock);

int npu_sched_submit(struct npu_device *dev, struct npu_job *job)
{
    unsigned long flags;
    int slot;

    spin_lock_irqsave(&npu_sched_lock, flags);

    slot = dev->sched.head;
    dev->sched.queue[slot] = job;
    dev->sched.head = (slot + 1) % NPU_MAX_JOBS;
    dev->sched.pending++;

    spin_unlock_irqrestore(&npu_sched_lock, flags);
    return slot;
}

struct npu_job *npu_sched_next(struct npu_device *dev)
{
    struct npu_job *job;
    unsigned long flags;

    spin_lock_irqsave(&npu_sched_lock, flags);

    job = dev->sched.queue[dev->sched.tail];
    dev->sched.queue[dev->sched.tail] = NULL;
    dev->sched.tail = (dev->sched.tail + 1) % NPU_MAX_JOBS;
    dev->sched.pending--;

    spin_unlock_irqrestore(&npu_sched_lock, flags);
    return job;
}
