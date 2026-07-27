/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2025, Unikraft GmbH and The Unikraft Authors.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

/*
 * Cooperative "poll" execution model for Hyperlight guests.
 * See include/hyperlight-x86/poll.h for the design rationale.
 */

#include <stdio.h>
#include <uk/arch/types.h>
#include <uk/arch/time.h>
#include <uk/plat/time.h>
#include <uk/essentials.h>
#include <uk/lcpu.h>
#include <uk/thread.h>
#include <uk/sched.h>
#include <uk/sched_impl.h>
#include <hyperlight-x86/hcall.h>
#include <hyperlight-x86/poll.h>
#include <hyperlight-x86/dispatch.h>
#include <hyperlight-x86/fb.h>

#define HYPERLIGHT_POLL_REPOLL_NS 1ULL

#ifdef CONFIG_LIBHOSTSOCK
/* Re-poll all host-proxied sockets and post readiness events, waking any
 * thread cooperatively parked on a socket (e.g. a blocking recv/accept that
 * returned EAGAIN and yielded via uk_file_poll). Defined in lib/hostsock.
 */
extern int hostsock_rescan_events(void);
#endif

/* The thread that the host `poll` invocation runs on. Captured on entry to
 * hyperlight_poll_pump() so the platform halt path can switch back to it.
 * NULL while no poll is in flight.
 */
static struct uk_thread *hl_poll_host_thread;

/* The scheduler idle thread driven by the current pump. Platform halt paths
 * use its identity to avoid intercepting waits made by application threads.
 */
static struct uk_thread *hl_poll_idle_thread;

/* Next-wakeup deadline recorded by the idle path and consumed by the pump
 * before it returns to the host.
 */
static __nsec hl_poll_wakeup_time;

/* Extract the first hlstring parameter from the in-flight `poll` FunctionCall
 * and deliver it as the completed/errored-task batch to any parked host calls.
 *
 * The host invokes the guest `poll` function with a single JSON string
 * argument: {"<request-id>":{"result":…}|{"error":…}, …} listing every async host
 * task that has completed or errored since the last poll (empty object when
 * none). hyperlight_hcall_deliver_batch() routes each entry to the matching
 * parked op. The FC bytes are the ones dispatch.c stashed for this call
 * (see hyperlight_dispatch_current_fc_*); parsing mirrors the fixed
 * FunctionCall/hlstring FlatBuffer shape used elsewhere (fb.h).
 */
static void hyperlight_poll_deliver_arg(void)
{
	const __u8 *b = hyperlight_dispatch_current_fc_bytes();
	__sz len = hyperlight_dispatch_current_fc_len();
	__sz fc, params, p0_pos, p0, hs, s;
	__u16 tf;
	__u32 slen;

	if (!b || len < 8)
		return;

	/* Root table (size-prefixed buffer: root offset at byte 4). */
	fc = 4 + hl_fb_u32(b, 4);

	/* parameters vector at VT[6] on FunctionCall. */
	params = hl_fb_follow(b, fc, 6);
	if (!params || hl_fb_u32(b, params) == 0)
		return; /* no argument — nothing to deliver */

	/* First parameter element (offset stored 4 bytes past the length). */
	p0_pos = params + 4;
	p0 = p0_pos + hl_fb_u32(b, p0_pos);

	/* Parameter.value_type (u8 inline at VT[4]) must be hlstring (7). */
	tf = hl_fb_field(b, p0, 4);
	if (!tf || b[p0 + tf] != HL_PV_HLSTRING)
		return;

	/* Parameter.value (VT[6]) -> hlstring table -> value (VT[4]) -> data. */
	hs = hl_fb_follow(b, p0, 6);
	if (!hs)
		return;
	s = hl_fb_follow(b, hs, 4);
	if (!s || s + 4 > len)
		return;
	slen = hl_fb_u32(b, s);
	if (s + 4 + slen > len)
		return;

	hyperlight_hcall_deliver_batch(b + s + 4, (__sz)slen);
}

static int hyperlight_poll_current_can_park(void)
{
	struct uk_thread *current;

	/* Only safe while a pump is driving the scheduler, and only for a
	 * schedulable thread other than the pump's own host thread (parking
	 * the host thread would deadlock the pump — it is what returns control
	 * to the host).
	 */
	if (!hl_poll_host_thread)
		return 0;

	current = uk_thread_current();
	if (!current || current == hl_poll_host_thread)
		return 0;

	return 1;
}

static int hyperlight_poll_idle_return(__nsec wakeup_time)
{
	if (!hl_poll_host_thread ||
	    uk_thread_current() != hl_poll_idle_thread)
		return 0;

	hl_poll_wakeup_time = wakeup_time;
	uk_sched_thread_switch(hl_poll_host_thread);
	return 1;
}

int hyperlight_poll_halt(__nsec wakeup_time)
{
	struct uk_thread *current;

	if (hyperlight_poll_idle_return(wakeup_time))
		return 1;
	if (!wakeup_time || !hyperlight_poll_current_can_park())
		return 0;

	current = uk_thread_current();
	UK_ASSERT(current);
	uk_thread_block_until(current, wakeup_time);
	uk_sched_yield();
	return 1;
}

int hyperlight_poll_park(void)
{
	struct uk_thread *current = uk_thread_current();

	if (!hyperlight_poll_current_can_park())
		return 0;
	uk_thread_block(current);
	uk_sched_yield();
	return 1;
}

/* Report the next-wakeup deadline to the host via a synchronous host
 * function call, mirroring the {"name":...,"args":{...}} convention used
 * by the rest of the Hyperlight tooling (see plat/hyperlight/hcall.c and
 * the host-side ToolRegistry).
 *
 *   ns: nanoseconds until the next timer fires (0 = no pending timer;
 *       1 = re-poll immediately when a real timer is already due).
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

	/* Remember both ends of the context switch and arm the platform halt
	 * interception. Tracking the idle thread ensures application-thread
	 * waits are never mistaken for the scheduler becoming idle.
	 */
	hl_poll_host_thread = uk_thread_current();
	hl_poll_idle_thread = idle;

	/* The cooperative scheduler requires IRQs enabled: schedcoop_schedule()
	 * asserts this, and the idle thread we switch into will call it. The
	 * guest `poll` dispatch enters with IRQs disabled, so enable them for
	 * the duration of the scheduler run and restore the caller's state once
	 * the idle path hands control back to us.
	 */
	flags = uk_lcpu_save_irqf();
	uk_lcpu_enable_irq();

	/* Deliver completed host calls and wake their matching guest threads. */
	hyperlight_poll_deliver_arg();

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
	 * the run queue drains it reaches its normal platform halt operation,
	 * which switches control back to us.
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
	wakeup_time = hl_poll_wakeup_time;
	hl_poll_host_thread = NULL;
	hl_poll_idle_thread = NULL;
	hl_poll_wakeup_time = 0;

	/* Translate the absolute deadline into a relative delay for the host.
	 * Reserve 0 exclusively for "no pending timer." A real deadline can
	 * become due while control switches from the idle thread back to this
	 * pump; report the minimum nonzero delay in that case so the host
	 * re-polls immediately instead of waiting indefinitely for external I/O.
	 */
	if (wakeup_time) {
		now = ukplat_monotonic_clock();
		ns = (wakeup_time > now) ? (__u64)(wakeup_time - now) :
			HYPERLIGHT_POLL_REPOLL_NS;
	} else {
		ns = 0;
	}

	hyperlight_poll_report(ns);
}
