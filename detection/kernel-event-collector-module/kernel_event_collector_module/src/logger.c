// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include <linux/time.h>
#include <linux/gfp.h>
#include "priv.h"
#include "mem-cache.h"
#include "cb-banning.h"
#include "process-tracking.h"
#include "version.h"

#pragma pack(push, 1)
typedef struct _logger_work {
    struct  work_struct     work;

    struct cn_msg           cnmsg;
    struct CB_EVENT         event;
}
logger_work, *plogger_work;
#pragma pack(pop)

static CB_MEM_CACHE s_event_cache;

static const struct timespec null_time = {0, 0};

uint64_t ec_to_windows_timestamp(const struct timespec *tv)
{
    return TO_WIN_TIME(tv->tv_sec, tv->tv_nsec);
}

struct timespec ec_get_current_timespec(void)
{
    struct timespec     current_time;

    getnstimeofday(&current_time);
    return current_time;
}

time_t ec_get_current_time(void)
{
    struct timespec     current_time;

    getnstimeofday(&current_time);
    return ec_to_windows_timestamp(&current_time);
}

time_t ec_get_null_time(void)
{
    return TO_WIN_TIME(0, 0);
}

void ec_free_event(PCB_EVENT event, ProcessContext *context)
{
    if (event)
    {
        CB_EVENT_NODE *node = container_of(event, CB_EVENT_NODE, data);

        // Free the stored process data
        //  This may cause a stored exit event to be sent if this is the last event
        //  for a process.
        ec_event_set_process_data(event, NULL, context);

        ec_mem_cache_free_generic(event->procInfo.path);
        event->procInfo.path = NULL;

        switch (event->eventType)
        {
        case CB_EVENT_TYPE_PROCESS_START:
            if (event->processStart.path)
            {
                ec_mem_cache_free_generic(event->processStart.path);
                event->processStart.path = NULL;
            }
            break;

        case CB_EVENT_TYPE_MODULE_LOAD:
            if (event->moduleLoad.path)
            {
                ec_mem_cache_free_generic(event->moduleLoad.path);
                event->moduleLoad.path = NULL;
            }
            break;

        case CB_EVENT_TYPE_FILE_CREATE:
        case CB_EVENT_TYPE_FILE_DELETE:
        case CB_EVENT_TYPE_FILE_OPEN:
        case CB_EVENT_TYPE_FILE_WRITE:
        case CB_EVENT_TYPE_FILE_CLOSE:
            if (event->fileGeneric.path)
            {
                ec_mem_cache_free_generic(event->fileGeneric.path);
                event->fileGeneric.path = NULL;
            }
            break;

        case CB_EVENT_TYPE_DNS_RESPONSE:
            if (event->dnsResponse.records)
            {
                ec_mem_cache_free_generic(event->dnsResponse.records);
                event->dnsResponse.records = NULL;
            }
            break;

        case CB_EVENT_TYPE_NET_CONNECT_PRE:
        case CB_EVENT_TYPE_NET_CONNECT_POST:
        case CB_EVENT_TYPE_NET_ACCEPT:
        case CB_EVENT_TYPE_WEB_PROXY:
            if (event->netConnect.actual_server)
            {
                ec_mem_cache_free_generic(event->netConnect.actual_server);
                event->netConnect.actual_server = NULL;
            }
            break;

        case CB_EVENT_TYPE_PROCESS_BLOCKED:
            if (event->blockResponse.path)
            {
                ec_mem_cache_free_generic(event->blockResponse.path);
                event->blockResponse.path = NULL;
            }
            break;

        default:
            break;
        }

        ec_mem_cache_free(&s_event_cache, node, context);
    }
}

void ec_event_set_process_data(PCB_EVENT event, void *process_data, ProcessContext *context)
{
    if (event)
    {
        CB_EVENT_NODE *node = container_of(event, CB_EVENT_NODE, data);

        // If we have something stored free it now
        ec_process_tracking_put_exec_identity(node->process_data, context);

        // Save the process data in the event node and increase the ref
        //  We don't actually do anything with this.  We only release it later.
        node->process_data = ec_process_tracking_get_exec_identity_ref(process_data, context);
    }
}

bool ec_logger_should_log(CB_INTENT_TYPE intentType, CB_EVENT_TYPE eventType)
{
    switch (eventType)
    {
    case CB_EVENT_TYPE_PROCESS_START_FORK:
        switch (g_driver_config.processes)
        {
        case COLLAPSED_EXITS_ALL_FORKS:
        case ALL_FORKS_AND_EXITS:
            return true;
        case EXECS_ONLY:
        case COLLAPSED_EXITS_NO_FORKS:
        case DISABLE:
        default:
            return false;
        }
        break;

    case CB_EVENT_TYPE_PROCESS_START_EXEC:
        return g_driver_config.processes != DISABLE;
        break;

    case CB_EVENT_TYPE_PROCESS_EXIT:
        switch (g_driver_config.processes)
        {
        case ALL_FORKS_AND_EXITS:
            return true;
        default:
            return false;
        }
        break;

    case CB_EVENT_TYPE_PROCESS_LAST_EXIT:
        switch (g_driver_config.processes)
        {
        case COLLAPSED_EXITS_ALL_FORKS:
        case ALL_FORKS_AND_EXITS:
        case COLLAPSED_EXITS_NO_FORKS:
            return true;
        case EXECS_ONLY:
        case DISABLE:
        default:
            return false;
        }
        break;

    case CB_EVENT_TYPE_MODULE_LOAD:
        return g_driver_config.module_loads == ENABLE;

    case CB_EVENT_TYPE_FILE_CREATE:
    case CB_EVENT_TYPE_FILE_DELETE:
    case CB_EVENT_TYPE_FILE_WRITE:
    case CB_EVENT_TYPE_FILE_CLOSE:
    case CB_EVENT_TYPE_FILE_OPEN:
        if (intentType == INTENT_PREACTION)
        {
            return g_driver_config.report_file_intent == ENABLE;
        }
        return (g_driver_config.file_mods == ENABLE);

    case CB_EVENT_TYPE_NET_CONNECT_PRE:
    case CB_EVENT_TYPE_NET_CONNECT_POST:
    case CB_EVENT_TYPE_NET_ACCEPT:
    case CB_EVENT_TYPE_DNS_RESPONSE:
        return g_driver_config.net_conns == ENABLE;

    case CB_EVENT_TYPE_PROCESS_BLOCKED:
    case CB_EVENT_TYPE_PROCESS_NOT_BLOCKED:
    case CB_EVENT_TYPE_HEARTBEAT:
    case CB_EVENT_TYPE_WEB_PROXY:
        return true;

    default:
        TRACE(DL_WARNING, "Unknown shouldlog event type %d", eventType);
        return true;
    }
}


bool ec_shouldExcludeByUID(ProcessContext *context, uid_t uid)
{
    if (g_edr_server_uid == uid)
    {
        return true;
    }

    return ec_banning_IgnoreUid(context, uid);
}

PCB_EVENT ec_alloc_event(CB_INTENT_TYPE intentType, CB_EVENT_TYPE eventType, ProcessContext *context)
{
    CB_EVENT_NODE *node = NULL;
    PCB_EVENT event = NULL;
    uid_t uid = GET_UID();
    CB_EVENT_TYPE resolvedEventType = eventType;

    // We use some semi-private event types to provide some extra granularity.
    //  Depending on the config structure, the ec_logger_should_log function may reject the
    //  event. The collector does not care about this extra granularitiy, so once
    //  we know the event should be logged, we set it to the more generic event type.
    TRY(ec_logger_should_log(intentType, eventType));
    switch (eventType)
    {
    case CB_EVENT_TYPE_PROCESS_START_FORK:
    case CB_EVENT_TYPE_PROCESS_START_EXEC:
        resolvedEventType = CB_EVENT_TYPE_PROCESS_START;
        break;
    default:
        break;
    }

    TRY(!ec_shouldExcludeByUID(context, uid));

    node = (CB_EVENT_NODE *)ec_mem_cache_alloc(&s_event_cache, context);

    TRY_DO(node, {
        TRACE(DL_WARNING, "Error allocating event with mode %s", IS_ATOMIC(context) ? "ATOMIC" : "KERNEL");
    });

    memset(node, 0, sizeof(*node));
    INIT_LIST_HEAD(&node->listEntry);

    node->process_data = NULL;
    event              = &node->data;

    event->apiVersion = CB_APP_API_VERSION;
    event->eventType  = resolvedEventType;
    event->canary     = 0;

    event->procInfo.event_time  = ec_get_current_time();
    event->procInfo.path_found = false;
    event->procInfo.path       = NULL;
    event->generic_data.data   = NULL;
    memset(&event->procInfo.all_process_details, 0, sizeof(AllProcessDetails));

CATCH_DEFAULT:
    return event;
}

void ec_free_event_on_error(PCB_EVENT event, ProcessContext *context)
{
    ec_free_event(event, context);
}

bool ec_logger_initialize(ProcessContext *context)
{
    TRACE(DL_INFO, "Initializing Logger");
    TRACE(DL_INFO, "CB_EVENT size is %ld (0x%lx)", sizeof(struct CB_EVENT), sizeof(struct CB_EVENT));

    if (!ec_mem_cache_create(&s_event_cache, "event_cache", sizeof(CB_EVENT_NODE), context))
    {
        return false;
    }

    return true;
}

void ec_logger_shutdown(ProcessContext *context)
{
    ec_mem_cache_destroy(&s_event_cache, context, NULL);
}

