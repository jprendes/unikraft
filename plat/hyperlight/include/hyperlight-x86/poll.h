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

#if CONFIG_HYPERLIGHT_POLL
#ifdef __cplusplus
extern "C" {
#endif

/**
 * Drive the scheduler until it would go idle, then return.
 *
 * Registered as the Hyperlight dispatch run-callback in poll mode (see
 * app-elfloader main.c). Called from hyperlight_dispatch_inner() on every
 * `poll` guest-function invocation. Switches into the scheduler so that
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
 * handled and the caller must use its legacy path.
 *
 * @param wakeup_time    Absolute monotonic-clock deadline of the next
 *                       sleeping thread, or 0 if none.
 * @return Non-zero if the halt was handled, otherwise zero.
 */
int hyperlight_poll_halt(__nsec wakeup_time);

/**
 * @return Non-zero if the caller can be parked and later resumed by a poll
 *         pump — i.e. a pump is in flight and the caller is a schedulable
 *         thread other than the pump's own host thread. Used by
 *         timer and host-call wait paths before suspending the current thread.
 */
int hyperlight_poll_current_can_park(void);

/**
 * Park the calling thread until the next poll pump, then return.
 *
 * Used by hyperlight_hcall() when a host function call reports that its
 * result is not ready ("yield"). The caller's stack (deep inside whatever
 * issued the host call) is preserved by the scheduler, so when the host
 * re-invokes `poll` and the pump wakes this thread, execution resumes right
 * where it parked and checks the completion batch delivered by the pump.
 *
 * Must only be called when hyperlight_poll_current_can_park() is true.
 */
void hyperlight_hcall_park_retry(void);

#ifdef __cplusplus
}
#endif
#else /* !CONFIG_HYPERLIGHT_POLL */
/* Keep poll-versus-legacy decisions inside the Hyperlight platform. Callers
 * use these hooks unconditionally; non-poll builds compile them away.
 */
static inline int hyperlight_poll_halt(__nsec wakeup_time)
{
	(void)wakeup_time;
	return 0;
}
#endif /* CONFIG_HYPERLIGHT_POLL */

#endif /* __HYPERLIGHT_X86_POLL_H__ */
