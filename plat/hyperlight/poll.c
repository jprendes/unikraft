/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2025, Unikraft GmbH and The Unikraft Authors.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

/*
 * Cooperative "poll" execution model for Hyperlight guests.
 * See include/hyperlight-x86/poll.h for the design rationale.
 */

#include <string.h>
#include <stdio.h>
#include <uk/arch/types.h>
#include <uk/arch/time.h>
#include <uk/plat/time.h>
#include <uk/print.h>
#include <uk/essentials.h>
#include <uk/lcpu.h>
#include <uk/thread.h>
#include <uk/sched.h>
#include <uk/sched_impl.h>
#include <hyperlight-x86/hcall.h>
#include <hyperlight-x86/poll.h>

#ifdef CONFIG_LIBHOSTSOCK
/* Re-poll all host-proxied sockets and post readiness events, waking any
 * thread cooperatively parked on a socket (e.g. a blocking recv/accept that
 * returned EAGAIN and yielded via uk_file_poll). Defined in lib/hostsock.
 */
extern int hostsock_rescan_events(void);
#endif

/* The thread that the host `poll` invocation runs on. Captured on entry to
 * hyperlight_poll_pump() so the scheduler idle path can switch back to it.
 * NULL while no poll is in flight.
 */
static struct uk_thread *hl_poll_host_thread;

/* Set for the duration of a poll pump so the scheduler idle path returns
 * to the host instead of halting the CPU in-guest.
 */
static volatile int hl_poll_in_flight;

/* Next-wakeup deadline recorded by the idle path and consumed by the pump
 * before it returns to the host.
 */
static volatile __nsec hl_poll_wakeup_time;

int hyperlight_poll_active(void)
{
	return hl_poll_in_flight;
}

/* Report the next-wakeup deadline to the host via a synchronous host
 * function call, mirroring the {"name":...,"args":{...}} convention used
 * by the rest of the Hyperlight tooling (see plat/hyperlight/hcall.c and
 * the host-side ToolRegistry).
 *
 *   ns: nanoseconds until the next timer fires (0 = no pending timer;
 *       the host waits for external input before re-polling).
 *
 * Completion is signalled separately by the application through the
 * existing __hl_exit host function, so it is not reported here. Failures
 * are non-fatal: the host falls back to an immediate re-poll.
 */
static void hyperlight_poll_report(__u64 ns)
{
	char req[96];
	__u8 resp[64];
	__sz resp_len = 0;
	int n;

	n = snprintf(req, sizeof(req),
		     "{\"name\":\"__hl_poll_yield\",\"args\":{\"ns\":%llu}}",
		     (unsigned long long)ns);
	if (n <= 0 || n >= (int)sizeof(req))
		return;

	(void)hyperlight_hcall((const __u8 *)req, (__sz)n,
			       resp, sizeof(resp), &resp_len);
}

void hyperlight_poll_pump(void)
{
	struct uk_sched *s = uk_sched_current();
	struct uk_thread *idle;
	__nsec wakeup_time;
	__nsec now;
	__u64 ns;
	unsigned long flags;

	if (unlikely(!s)) {
		/* No scheduler to drive: report "no timer" so the host does
		 * not busy-loop, and let the application signal completion
		 * via __hl_exit.
		 */
		hyperlight_poll_report(0);
		return;
	}

	/* Fetch the scheduler idle thread via the generic sched op accessor
	 * (dispatches through the registered idle_thread callback). The const
	 * is dropped because uk_sched_thread_switch() needs a mutable handle;
	 * the idle thread object is legitimately mutable.
	 */
	idle = (struct uk_thread *)uk_sched_idle_thread(s, 0);
	if (unlikely(!idle)) {
		hyperlight_poll_report(0);
		return;
	}

	/* Remember the thread we are running on so the idle path can switch
	 * back to it, and arm the idle hook.
	 */
	hl_poll_host_thread = uk_thread_current();
	hl_poll_in_flight = 1;

	/* The cooperative scheduler requires IRQs enabled: schedcoop_schedule()
	 * asserts this, and the idle thread we switch into will call it. The
	 * guest `poll` dispatch enters with IRQs disabled, so enable them for
	 * the duration of the scheduler run and restore the caller's state once
	 * the idle path hands control back to us.
	 */
	flags = uk_lcpu_save_irqf();
	uk_lcpu_enable_irq();

#ifdef CONFIG_LIBHOSTSOCK
	/* A host `poll` re-entry is our chance to observe socket I/O that
	 * arrived while the vCPU was yielded to the host. Refresh readiness
	 * for all tracked host sockets so any thread parked on one (a
	 * cooperative recv/accept wait) is woken and re-run below.
	 */
	hostsock_rescan_events();
#endif

	/* Switch directly into the scheduler idle thread. It drives every
	 * runnable thread cooperatively (idle yields to the run queue); when
	 * the run queue drains it reaches its halt point, where
	 * hyperlight_poll_idle_return() switches control back to us.
	 *
	 * Entering via the idle thread (rather than yielding from the host
	 * thread) guarantees the scheduler reaches idle even though the host
	 * thread remains "current" — the host thread is never offered to the
	 * run queue, so it cannot be re-selected ahead of idle.
	 */
	uk_sched_thread_switch(idle);

	/* Back from the idle path (IRQs disabled inside idle's critical
	 * section); restore the IRQ state the dispatch entered with.
	 */
	uk_lcpu_restore_irqf(flags);

	/* Snapshot and clear the shared state. */
	hl_poll_in_flight = 0;
	wakeup_time = hl_poll_wakeup_time;
	hl_poll_host_thread = NULL;
	hl_poll_wakeup_time = 0;

	/* Translate the absolute deadline into a relative delay for the
	 * host. 0 means "no pending timer" (host waits for external input).
	 */
	if (wakeup_time) {
		now = ukplat_monotonic_clock();
		ns = (wakeup_time > now) ? (__u64)(wakeup_time - now) : 0;
	} else {
		ns = 0;
	}

	hyperlight_poll_report(ns);
}

void hyperlight_poll_idle_return(struct uk_sched *s, __nsec wakeup_time)
{
	/* Only act inside a poll pump; otherwise return so the caller uses
	 * the legacy in-guest halt path.
	 */
	if (!hl_poll_in_flight || !hl_poll_host_thread)
		return;

	hl_poll_wakeup_time = wakeup_time;

	/* Switch back to the thread that called hyperlight_poll_pump(). This
	 * saves the idle thread's context, so the next `poll` resumes the
	 * idle thread right here and it re-checks the run queue.
	 */
	(void)s;
	uk_sched_thread_switch(hl_poll_host_thread);
}
