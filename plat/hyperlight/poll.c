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
#include <uk/alloc.h>
#include <uk/print.h>
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

/* The thread that runs application-registered named calls, and the call it
 * has been handed. See hyperlight_poll_dispatch_worker().
 */
static struct uk_thread *hl_poll_worker_thread;
static __u8 *hl_poll_call_fc;
static __sz hl_poll_call_fc_len;

/* Set once the worker finishes a named call, consumed by the pump. */
static int hl_poll_call_done;

/* Name of the guest function that drives the scheduler. Anything else is an
 * application-level call to be routed to the FC-aware dispatch callback.
 */
static const char hl_poll_fn_name[] = "poll";

/* Locate the root FunctionCall table of a size-prefixed buffer. Returns 0
 * when the buffer is too short to hold one.
 */
static __sz hl_poll_fc_root(const __u8 *b, __sz len)
{
	__sz fc;

	if (!b || len < 8)
		return 0;
	fc = 4 + hl_fb_u32(b, 4);

	return (fc < len) ? fc : 0;
}

/* True if the in-flight FunctionCall is the scheduler pump entry point. */
static int hl_poll_fc_is_pump(const __u8 *b, __sz len)
{
	__sz fc = hl_poll_fc_root(b, len);
	__sz name;
	__u32 nlen;

	if (!fc)
		return 0;

	/* FunctionCall.function_name is a string at VT[4]. */
	name = hl_fb_follow(b, fc, 4);
	if (!name || name + 4 > len)
		return 0;
	nlen = hl_fb_u32(b, name);
	if (name + 4 + nlen > len || nlen != sizeof(hl_poll_fn_name) - 1)
		return 0;

	return !__builtin_memcmp(b + name + 4, hl_poll_fn_name, nlen);
}

/* Hand a named FunctionCall to the dispatch worker and make it runnable.
 *
 * The bytes are copied because they live on the PEB input stack, which the
 * host reuses for host-call responses: the very first host call the
 * application makes would otherwise overwrite the arguments it is still
 * reading. The copy is released once the worker has consumed it.
 */
static void hl_poll_route_call(const __u8 *b, __sz len)
{
	__u8 *copy;

	if (!hl_poll_worker_thread || !b || !len)
		return;

	/* Before the application registers a handler its own startup path owns
	 * the call: the first guest function is what runs main(). Routing it
	 * would report a completion nobody performed.
	 */
	if (!*hyperlight_dispatch_v2_slot())
		return;

	/* One call is in flight at a time: the host cannot issue another
	 * guest function until this pump returns, and the worker only parks
	 * again after reporting completion.
	 */
	if (hl_poll_call_fc)
		return;

	copy = uk_malloc(uk_alloc_get_default(), len);
	if (unlikely(!copy)) {
		uk_pr_err("hyperlight: no memory to route a %" __PRIsz
			  "-byte guest call\n", len);
		return;
	}
	__builtin_memcpy(copy, b, len);

	hl_poll_call_fc = copy;
	hl_poll_call_fc_len = len;
	uk_thread_wake(hl_poll_worker_thread);
}

void hyperlight_poll_set_dispatch_worker(struct uk_thread *t)
{
	hl_poll_worker_thread = t;
}

void hyperlight_poll_dispatch_worker(void)
{
	for (;;) {
		__u8 *fc;
		__sz fc_len;

		while (!hl_poll_call_fc) {
			uk_thread_block(uk_thread_current());
			uk_sched_yield();
		}

		fc = hl_poll_call_fc;
		fc_len = hl_poll_call_fc_len;

		/* Only a call that actually ran counts as complete. */
		if (hyperlight_dispatch_invoke_v2(fc, fc_len)) {
			/* Tell the host the call it asked for has finished.
			 * Reported by the pump on its next return, which is at
			 * the latest when this thread parks below and the
			 * scheduler goes idle.
			 */
			hl_poll_call_done = 1;
		}

		hl_poll_call_fc = NULL;
		hl_poll_call_fc_len = 0;
		uk_free(uk_alloc_get_default(), fc);
	}
}

/* Extract the first hlvecbytes parameter from the in-flight `poll`
 * FunctionCall and deliver it as the completed-task batch.
 *
 * The host invokes `poll` with one binary frame containing every async result
 * ready for delivery. hyperlight_hcall_deliver_batch() validates and routes
 * its entries. The FC bytes are the ones dispatch.c stashed for this call.
 */
static void hyperlight_poll_deliver_arg(const __u8 *b, __sz len)
{
	__sz fc, params, p0_pos, p0, vb, v;
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

	/* Parameter.value_type (u8 inline at VT[4]) must be hlvecbytes (9). */
	tf = hl_fb_field(b, p0, 4);
	if (!tf || b[p0 + tf] != HL_PV_HLVECBYTES)
		return;

	/* Parameter.value (VT[6]) -> hlvecbytes table -> value (VT[4]). */
	vb = hl_fb_follow(b, p0, 6);
	if (!vb)
		return;
	v = hl_fb_follow(b, vb, 4);
	if (!v || v + 4 > len)
		return;
	slen = hl_fb_u32(b, v);
	if (v + 4 + slen > len)
		return;

	hyperlight_hcall_deliver_batch(b + v + 4, (__sz)slen);
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
 *   call_done: a named guest function invoked through the dispatch worker
 *       has returned, so the host call that requested it is complete.
 *
 * Process exit is signalled separately by the application through the
 * existing __hl_exit host function, so it is not reported here. Failures
 * are non-fatal: the host falls back to an immediate re-poll.
 */
static void hyperlight_poll_report(__u64 ns, int call_done)
{
	char req[128];
	__u8 resp[64];
	__sz resp_len = 0;
	int n;

	n = snprintf(req, sizeof(req),
		     "{\"name\":\"__hl_poll_yield\",\"args\":"
		     "{\"ns\":%llu,\"call_done\":%s}}",
		     (unsigned long long)ns, call_done ? "true" : "false");
	if (n <= 0 || n >= (int)sizeof(req))
		return;

	(void)hyperlight_hcall((const __u8 *)req, (__sz)n,
			       resp, sizeof(resp), &resp_len);
}

void hyperlight_poll_pump(void)
{
	struct uk_sched *s = uk_sched_current();
	const __u8 *fc = hyperlight_dispatch_current_fc_bytes();
	__sz fc_len = hyperlight_dispatch_current_fc_len();
	struct uk_thread *idle;
	__nsec wakeup_time;
	__nsec now;
	__u64 ns;
	unsigned long flags;
	int call_done;

	if (unlikely(!s)) {
		/* No scheduler to drive: report "no timer" so the host does
		 * not busy-loop, and let the application signal completion
		 * via __hl_exit.
		 */
		hyperlight_poll_report(0, 0);
		return;
	}

	/* Fetch the scheduler idle thread via the generic sched op accessor
	 * (dispatches through the registered idle_thread callback). The const
	 * is dropped because uk_sched_thread_switch() needs a mutable handle;
	 * the idle thread object is legitimately mutable.
	 */
	idle = (struct uk_thread *)uk_sched_idle_thread(s, 0);
	if (unlikely(!idle)) {
		hyperlight_poll_report(0, 0);
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

	/* Every guest function reaches the pump. `poll` carries the batch of
	 * completed host calls; any other name is an application-level call
	 * that the dispatch worker runs on the scheduler.
	 */
	if (hl_poll_fc_is_pump(fc, fc_len))
		hyperlight_poll_deliver_arg(fc, fc_len);
	else
		hl_poll_route_call(fc, fc_len);

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
	call_done = hl_poll_call_done;
	hl_poll_host_thread = NULL;
	hl_poll_idle_thread = NULL;
	hl_poll_wakeup_time = 0;
	hl_poll_call_done = 0;

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

	hyperlight_poll_report(ns, call_done);
}
