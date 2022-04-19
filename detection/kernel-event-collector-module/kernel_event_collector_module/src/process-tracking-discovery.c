// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "process-tracking-private.h"
#include "cb-test.h"
#include "event-factory.h"
#include "priv.h"
#include "cb-spinlock.h"

void __ec_send_process_discovery(void *data, void *priv, ProcessContext *context);

void ec_process_tracking_send_process_discovery(ProcessContext *context)
{
    // Because this can add events to the queue, we want to treat this like a
    // hook and make sure it is done before allowing the module to be disabled.
    // Otherwise, we can leak process entries, hang or crash the system by
    // disabling the driver while this function is in progress.
    MODULE_GET_AND_BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(context, CATCH_DEFAULT);

    // The call below will evqueue events while holding the hash table lack.  We
    //  observeved a deadlock with this logic in the following condition.
    //    The user agent triggers a process discover via the ioctl. (This code is called.)
    //      During this, we are holding a lock on the hash table.
    //    Meanwhile, we observe a fork and attempt to lock the hash table. But the
    //      discovery code holds the lock, so the clone hook is blocked.
    //    The discovery enqueues an event, and attempts to wake up the reader.
    //      This deadlocks because the clone hook has the scheduler frozen, but is
    //      waiting on us to release the lock.
    //    The fix is to ensure that we do not wake up the reader with the lock held.
    //    We explicitly wake up the reader after we have relased the lock, and
    //      enable the wake up logic.
    DISABLE_WAKE_UP(context);
    ec_sorted_tracking_table_for_each(__ec_send_process_discovery, NULL, context);
    ENABLE_WAKE_UP(context);

    ec_fops_comm_wake_up_reader(context);

CATCH_DEFAULT:
    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(context);
}

void __ec_send_process_discovery(void *data, void *priv, ProcessContext *context)
{
    ProcessHandle *handle = ec_sorted_tracking_table_get_handle(data, context);

    TRY(handle);

    ec_event_send_start(handle,
                    ec_process_tracking_should_track_user() ? ec_process_posix_identity(handle)->uid : (uid_t)-1,
                    CB_PROCESS_START_BY_DISCOVER,
                    context);

CATCH_DEFAULT:
    ec_process_tracking_put_handle(handle, context);
    return;
}
