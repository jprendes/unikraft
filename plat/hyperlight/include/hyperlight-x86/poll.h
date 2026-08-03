/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2025, Unikraft GmbH and The Unikraft Authors.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

/*
 * Cooperative "poll" execution model for Hyperlight guests.
 *
 * Instead of running a guest function to full completion in a single VM
 * entry (see plat/hyperlight/dispatch.c), the poll model runs the
 * unikernel scheduler until it would go idle, then returns from the guest
 * function after reporting a next-wakeup deadline. The host then re-invokes
 * the `poll` guest function to make further progress.
 *
 * This is safe with the register-reset re-entry that Hyperlight performs
 * on every guest-function call, because we only ever hand control back at
 * the scheduler-idle point: at that instant every runnable thread's CPU
 * context has already been saved into its TCB in guest memory, which is
 * preserved across the HALT. The transient scheduler/idle stack that the
 * host resets carries no state that must survive.
 */

#ifndef __HYPERLIGHT_X86_POLL_H__
#define __HYPERLIGHT_X86_POLL_H__

#include <uk/arch/types.h>

struct uk_thread;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Drive the scheduler until it would go idle, then return.
 *
 * Registered as the Hyperlight dispatch pump callback (see app-elfloader
 * main.c). Called from hyperlight_dispatch_inner() on every `poll`
 * guest-function invocation. Switches into the scheduler so that
 * runnable threads execute cooperatively. When the run queue drains, the
 * idle thread's normal timed or untimed platform halt operation switches
 * back here. Before returning, the pump reports the next-wakeup deadline
 * via a host function call.
 */
void hyperlight_poll_pump(void);

/**
 * Handle a platform halt while a poll pump is active.
 *
 * The pump's idle thread returns to the host with @wakeup_time as its next
 * deadline. For a nonzero deadline, an application thread is instead parked
 * in the guest scheduler until that time. Outside a poll pump the halt is not
 * handled and the caller must halt the vCPU itself.
 *
 * @param wakeup_time    Absolute monotonic-clock deadline of the next
 *                       sleeping thread, or 0 if none.
 * @return Non-zero if the halt was handled, otherwise zero.
 */
int hyperlight_poll_halt(__nsec wakeup_time);

/**
 * Park the calling thread until explicitly woken.
 *
 * @return Non-zero if the caller was parked and resumed, otherwise zero.
 */
int hyperlight_poll_park(void);

/**
 * Entry point of the dispatch worker thread.
 *
 * Named guest functions cannot run on the pump's own thread: that thread is
 * what returns control to the host, so a call that blocked there could never
 * yield the vCPU. app-elfloader creates one schedulable thread running this
 * loop; the pump hands it each named FunctionCall and it invokes the
 * application's FC-aware dispatch callback. Never returns.
 */
void hyperlight_poll_dispatch_worker(void);

/**
 * Nominate the thread running hyperlight_poll_dispatch_worker().
 *
 * Until a worker is registered, named calls are left for the application's
 * own startup path (the first call enters through main()).
 */
void hyperlight_poll_set_dispatch_worker(struct uk_thread *t);

#ifdef __cplusplus
}
#endif

#endif /* __HYPERLIGHT_X86_POLL_H__ */
