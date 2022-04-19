// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "cb-spinlock.h"
#include "mem-cache.h"
#include "task-helper.h"

#include <linux/version.h>
#include <linux/gfp.h>
#include <linux/spinlock.h>

// Enable lock debug output
// #define DEADLOCK_DBG

// We have the option to use rw locks or standard spinlocks
// #define CB_ENABLE_RWLOCK

// We have the option to either disable interrupts or not
// #define CB_ENABLE_GFP_BASED_LOCKS

#ifdef DEADLOCK_DBG
#   define DO_FOR_DEBUG(BLOCK) BLOCK
#else
#   define DO_FOR_DEBUG(BLOCK)
#endif

#ifdef CB_ENABLE_GFP_BASED_LOCKS
    #define LOCK_OP(LOCK, FLAGS, CONTEXT, LOCK_SAVE, LOCK_NO_SAVE) \
        do {\
            if (IS_ATOMIC(CONTEXT)) {\
                LOCK_SAVE(LOCK, FLAGS);\
            } else {\
                LOCK_NO_SAVE(LOCK);\
            } \
        } while (0)
#else
    #define LOCK_OP(LOCK, FLAGS, CONTEXT, LOCK_SAVE, LOCK_NO_SAVE) \
        LOCK_SAVE(LOCK, FLAGS)
#endif

#ifdef CB_ENABLE_RWLOCK
    #define LOCK_TYPE            rwlock_t
    #define LOCK_INIT            rwlock_init
    #define LOCK_UNLOCKED        RW_LOCK_UNLOCKED

    #define READ_LOCK_SAVE       read_lock_irqsave
    #define READ_LOCK_NO_SAVE    read_lock
    #define READ_UNLOCK_SAVE     read_unlock_irqrestore
    #define READ_UNLOCK_NO_SAVE  read_unlock
    #define READ_CAN_LOCK(LOCK)  read_can_lock(LOCK)

    #define WRITE_LOCK_SAVE      write_lock_irqsave
    #define WRITE_LOCK_NO_SAVE   write_lock
    #define WRITE_UNLOCK_SAVE    write_unlock_irqrestore
    #define WRITE_UNLOCK_NO_SAVE write_unlock
    #define WRITE_CAN_LOCK(LOCK) write_can_lock(LOCK)
#else
    // checkpatch-ignore: USE_LOCKDEP
    #define LOCK_TYPE            spinlock_t
    #define LOCK_INIT            spin_lock_init
    #define LOCK_UNLOCKED        SPIN_LOCK_UNLOCKED

    #define READ_LOCK_SAVE       spin_lock_irqsave
    #define READ_LOCK_NO_SAVE    spin_lock
    #define READ_UNLOCK_SAVE     spin_unlock_irqrestore
    #define READ_UNLOCK_NO_SAVE  spin_unlock
    #define READ_CAN_LOCK(LOCK)  !spin_is_locked(LOCK)

    #define WRITE_LOCK_SAVE      spin_lock_irqsave
    #define WRITE_LOCK_NO_SAVE   spin_lock
    #define WRITE_UNLOCK_SAVE    spin_unlock_irqrestore
    #define WRITE_UNLOCK_NO_SAVE spin_unlock
    #define WRITE_CAN_LOCK(LOCK) !spin_is_locked(LOCK)
    // checkpatch-no-ignore: USE_LOCKDEP
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#   define SPINLOCK_INIT(LOCK) LOCK_INIT(&LOCK)
#else
#   define SPINLOCK_INIT(LOCK) (LOCK = LOCK_UNLOCKED)
#endif

#define WRITE_LOCK(LOCK, FLAGS, CONTEXT)   LOCK_OP(LOCK, FLAGS, CONTEXT, WRITE_LOCK_SAVE,  WRITE_LOCK_NO_SAVE)
#define WRITE_UNLOCK(LOCK, FLAGS, CONTEXT) LOCK_OP(LOCK, FLAGS, CONTEXT, WRITE_UNLOCK_SAVE, WRITE_UNLOCK_NO_SAVE)
#define READ_LOCK(LOCK, FLAGS, CONTEXT)    LOCK_OP(LOCK, FLAGS, CONTEXT, READ_LOCK_SAVE,   READ_LOCK_NO_SAVE)
#define READ_UNLOCK(LOCK, FLAGS, CONTEXT)  LOCK_OP(LOCK, FLAGS, CONTEXT, READ_UNLOCK_SAVE, READ_UNLOCK_NO_SAVE)



typedef struct {
    LOCK_TYPE sp;
    pid_t create_pid;
    pid_t owner_pid;
    unsigned long flags;
} linuxSpinlock_t;

void ec_spinlock_init(uint64_t *sp, ProcessContext *context)
{
    linuxSpinlock_t *new_spinlock = ec_mem_cache_alloc_generic(sizeof(linuxSpinlock_t), context);

    if (new_spinlock)
    {
        SPINLOCK_INIT(new_spinlock->sp);
        new_spinlock->create_pid = ec_gettid(current);
        new_spinlock->owner_pid  = 0;
        new_spinlock->flags      = 0;
        *sp = (uint64_t)new_spinlock;
    } else
    {
        pr_err("%s failed initialize spinlock pid=%d\n", __func__, ec_gettid(current));
        *sp = 0;
    }
}

void ec_write_lock(uint64_t *sp, ProcessContext *context)
{
    linuxSpinlock_t *spinlockp = (linuxSpinlock_t *)*sp;
    pid_t tid = ec_gettid(current);

    DO_FOR_DEBUG({
        if (spinlockp->owner_pid == tid && !WRITE_CAN_LOCK(&spinlockp->sp))
        {
            pr_err("%s already LOCKED pid=%d owner=%d\n", __func__, tid, spinlockp->owner_pid);
        }
    });

    WRITE_LOCK(&spinlockp->sp, spinlockp->flags, context);
    PUSH_GFP_MODE(context, CB_ATOMIC);

    if (spinlockp->owner_pid == 0)
    {
        spinlockp->owner_pid = tid;
    }
}

void ec_write_unlock(uint64_t *sp, ProcessContext *context)
{
    linuxSpinlock_t *spinlockp = (linuxSpinlock_t *)*sp;

    DO_FOR_DEBUG({
        if ((spinlockp->owner_pid != 0 && spinlockp->owner_pid != ec_gettid(current)) ||
            WRITE_CAN_LOCK(&spinlockp->sp))
        {
            pr_err("%s already UNLOCKED pid=%d owner=%d\n", __func__, ec_gettid(current), spinlockp->owner_pid);
        }
    });

    spinlockp->owner_pid = 0;

    POP_GFP_MODE(context);
    WRITE_UNLOCK(&spinlockp->sp, spinlockp->flags, context);
}

void ec_read_lock(uint64_t *sp, ProcessContext *context)
{
    linuxSpinlock_t *spinlockp = (linuxSpinlock_t *)*sp;
    pid_t tid = ec_gettid(current);

    DO_FOR_DEBUG({
        if (spinlockp->owner_pid == tid && !READ_CAN_LOCK(&spinlockp->sp))
        {
            pr_err("%s already LOCKED pid=%d owner=%d\n", __func__, tid, spinlockp->owner_pid);
        }
    });

    READ_LOCK(&spinlockp->sp, spinlockp->flags, context);
    PUSH_GFP_MODE(context, CB_ATOMIC);

    if (spinlockp->owner_pid == 0)
    {
        spinlockp->owner_pid = tid;
    }
}

void ec_read_unlock(uint64_t *sp, ProcessContext *context)
{
    linuxSpinlock_t *spinlockp = (linuxSpinlock_t *)*sp;

    DO_FOR_DEBUG({
        if ((spinlockp->owner_pid != 0 && spinlockp->owner_pid != ec_gettid(current)) ||
            WRITE_CAN_LOCK(&spinlockp->sp))//If write can lock, we can not have the read lock.  (Best I can do.)
        {
            pr_err("%s already UNLOCKED pid=%d owner=%d\n", __func__, ec_gettid(current), spinlockp->owner_pid);
        }
    });

    spinlockp->owner_pid = 0;

    POP_GFP_MODE(context);
    READ_UNLOCK(&spinlockp->sp, spinlockp->flags, context);
}

void ec_spinlock_destroy(uint64_t *sp, ProcessContext *context)
{
    linuxSpinlock_t *spinlockp = (linuxSpinlock_t *)*sp;

    DO_FOR_DEBUG({
        if (!WRITE_CAN_LOCK(&spinlockp->sp))
        {
            pr_err("%s LOCKED and being destroyed pid=%d owner=%d\n", __func__, ec_gettid(current), spinlockp->owner_pid);
        }
    });
    //  pr_err("%s sp=%p\n", __FUNCTION__, spinlockp);
    ec_mem_cache_free_generic((linuxSpinlock_t *)spinlockp);
}
