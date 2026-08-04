/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2025, Unikraft GmbH and The Unikraft Authors.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

/*
 * Cooperative "poll" execution model for Hyperlight guests.
 *
 * Rather than run a guest function to completion in one VM entry (see
 * dispatch.c), the poll model runs the scheduler until it would go idle,
 * then returns to the host with a next-wakeup deadline. The host re-invokes
 * the `poll` guest function to make further progress.
 *
 * This survives the register reset Hyperlight performs on every entry
 * because control is only ever handed back at the scheduler-idle point, at
 * which every runnable thread's context is already saved in its TCB in guest
 * memory. Only the transient scheduler/idle stack is lost, and it holds
 * nothing that must survive.
 */

#ifndef __HYPERLIGHT_X86_POLL_H__
#define __HYPERLIGHT_X86_POLL_H__

#include <uk/arch/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct uk_thread;

/**
 * Drive the scheduler until it would go idle, then return.
 *
 * Registered as the dispatch pump callback (see app-elfloader main.c) and so
 * reached on *every* guest function: the pump itself tells the `poll` entry
 * point (which carries a batch of completed host calls) from an
 * application-level named call, which it routes to the dispatch worker. The
 * idle thread's platform halt hands control back here, and the pump then
 * reports the next-wakeup deadline via a host call.
 */
void hyperlight_poll_pump(void);

/**
 * Handle a platform halt while a poll pump is active.
 *
 * The pump's idle thread returns to the host with @wakeup_time as its next
 * deadline; any other thread with a nonzero deadline is instead parked in the
 * guest scheduler until then. Outside a pump the halt is not handled and the
 * caller must halt the vCPU itself.
 *
 * @param wakeup_time Absolute monotonic-clock deadline, or 0 if none.
 * @return Non-zero if the halt was handled.
 */
int hyperlight_poll_halt(__nsec wakeup_time);

/**
 * Park the calling thread until explicitly woken.
 *
 * @return Non-zero if the caller was parked and resumed.
 */
int hyperlight_poll_park(void);

/**
 * Entry point of the dispatch worker thread. Never returns.
 *
 * Named guest functions cannot run on the pump's own thread, which is what
 * returns control to the host: a call blocking there could never yield the
 * vCPU. app-elfloader runs this loop on a schedulable thread instead, and the
 * pump hands it each named FunctionCall to invoke the application's callback.
 */
void hyperlight_poll_dispatch_worker(void);

/**
 * Nominate the thread running hyperlight_poll_dispatch_worker().
 *
 * Must happen when the worker is created, not when it first runs: the host
 * may snapshot before the scheduler has ever run the worker, and a named call
 * arriving on restore would then be dropped. Until a worker is registered,
 * named calls are left to the application's own startup path (the first call
 * enters through main()).
 */
void hyperlight_poll_set_dispatch_worker(struct uk_thread *t);

#ifdef __cplusplus
}
#endif

#endif /* __HYPERLIGHT_X86_POLL_H__ */
