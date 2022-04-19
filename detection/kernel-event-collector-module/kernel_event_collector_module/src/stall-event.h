/* SPDX-License-Identifier: GPL-2.0 */
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#pragma once


// Basic Setup/Tear Down
extern bool ec_stall_events_initialize(ProcessContext *context);

extern void ec_stall_events_shutdown(ProcessContext *context);

// Call when CB_EVENT queue is requested to be cleared by userspace
extern void ec_stall_events_flush(ProcessContext *context);

// Config driven toggle switches
extern void ec_enable_stall_events(void);

extern void ec_disable_stall_events(ProcessContext *context);

// Check toggle switch value
extern bool ec_stall_events_enabled(void);


// Event Factory Helper To Set Next Permission Id
extern uint64_t ec_next_perm_id(void);


// Call when critical failure along CB_EVENT pipeline
extern int ec_stall_event_abort(uint64_t perm_id, pid_t tid, CB_EVENT_TYPE eventType,
                                ProcessContext *context);

// Handled replies from usrspace
extern int ec_stall_event_resume(struct CB_PERM_RESPONSE *perm_response,
                                 ProcessContext *context);


// Different ways we will want to stall tasks
extern int ec_wait_stall_event_killable(uint64_t perm_id, pid_t tid,
                                        CB_EVENT_TYPE eventType, ProcessContext *context);

extern int ec_wait_stall_event_timeout(uint64_t perm_id, pid_t tid, CB_EVENT_TYPE eventType,
                                       unsigned int ms, ProcessContext *context);

// RHEL8+ Only
extern int ec_wait_stall_event_killable_timeout(uint64_t perm_id, pid_t tid,
                                                CB_EVENT_TYPE eventType, unsigned int ms,
                                                ProcessContext *context);

// Helper to know if we can even stall from this context
extern bool ec_current_task_may_stall(void);
