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
 * unikernel scheduler until it would go idle, then exits the VM back to
 * the host (the ordinary HALT / port-108 exit) carrying a next-wakeup
 * deadline. The host then re-invokes the `poll` guest function to make
 * further progress.
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

#ifdef __cplusplus
extern "C" {
#endif

struct uk_sched;

/**
 * Drive the scheduler until it would go idle, then return.
 *
 * Registered as the Hyperlight dispatch run-callback in poll mode (see
 * app-elfloader main.c). Called from hyperlight_dispatch_inner() on every
 * `poll` guest-function invocation. Switches into the scheduler so that
 * runnable threads execute cooperatively; when the run queue drains, the
 * scheduler idle path calls hyperlight_poll_idle_return() which switches
 * back here. Before returning (and thus HALTing to the host), the pump
 * reports the next-wakeup deadline via a host function call.
 */
void hyperlight_poll_pump(void);

/**
 * Hand control back to the host from the scheduler idle path.
 *
 * Called by the cooperative scheduler (lib/ukschedcoop) when it has
 * nothing runnable and would otherwise halt the CPU in-guest. Records the
 * scheduler's next-wakeup deadline (0 = no pending timer) and switches
 * back to the context saved by hyperlight_poll_pump(). Execution resumes
 * inside this function on the next `poll`, at which point it returns so
 * the idle thread re-checks the run queue.
 *
 * @param s              The current cooperative scheduler.
 * @param wakeup_time    Absolute monotonic-clock deadline of the next
 *                       sleeping thread, or 0 if none.
 */
void hyperlight_poll_idle_return(struct uk_sched *s, __nsec wakeup_time);

/**
 * @return Non-zero while a poll pump is driving the scheduler. Used by the
 *         scheduler idle path to decide whether to return to the host
 *         (poll model) or halt the CPU in-guest (legacy model).
 */
int hyperlight_poll_active(void);

/**
 * @return Non-zero if the caller can be parked and later resumed by a poll
 *         pump — i.e. a pump is in flight and the caller is a schedulable
 *         thread other than the pump's own host thread. Used by
 *         hyperlight_hcall() to decide whether a "yield" host response can
 *         be honoured by suspending the caller (see
 *         hyperlight_hcall_park_retry).
 */
int hyperlight_hcall_can_yield(void);

/**
 * Park the calling thread until the next poll pump, then return.
 *
 * Used by hyperlight_hcall() when a host function call reports that its
 * result is not ready ("yield"). The caller's stack (deep inside whatever
 * issued the host call) is preserved by the scheduler, so when the host
 * re-invokes `poll` and the pump wakes this thread, execution resumes right
 * where it parked and the caller re-issues the host call to fetch the
 * now-maybe-ready result.
 *
 * Must only be called when hyperlight_hcall_can_yield() is true.
 */
void hyperlight_hcall_park_retry(void);

#ifdef __cplusplus
}
#endif

#endif /* __HYPERLIGHT_X86_POLL_H__ */
