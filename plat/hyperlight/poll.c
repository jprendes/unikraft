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

/* Pump state, meaningful only while a pump is in flight.
 *
 * The host thread is the one the `poll` invocation runs on, captured so the
 * platform halt path can switch back to it. Tracking the idle thread keeps
 * that path from mistaking an application thread's wait for the run queue
 * draining. The idle path records its next-wakeup deadline there for the pump
 * to report before it returns to the host.
 */
static struct uk_thread *hl_poll_host_thread;
static struct uk_thread *hl_poll_idle_thread;
static __nsec hl_poll_wakeup_time;

/* The thread that runs application-registered named calls, the call it has
 * been handed, and the flag it sets once one completes (consumed by the pump).
 * See hyperlight_poll_dispatch_worker().
 */
static struct uk_thread *hl_poll_worker_thread;
static __u8 *hl_poll_call_fc;
static __sz hl_poll_call_fc_len;
static int hl_poll_call_done;

/* The guest function that drives the scheduler. Any other name is an
 * application-level call for the FC-aware dispatch callback.
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

/* True if the FunctionCall rooted at @fc is the scheduler pump entry point. */
static int hl_poll_fc_is_pump(const __u8 *b, __sz len, __sz fc)
{
	__sz name;
	__u32 nlen;

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
 * host reuses for host-call responses: the application's very first host call
 * would otherwise overwrite the arguments it is still reading. The copy is
 * released once the worker has consumed it.
 */
static void hl_poll_route_call(const __u8 *b, __sz len)
{
	__u8 *copy;

	if (!hl_poll_worker_thread || !b || !len)
		return;

	/* Before the application registers a handler, its own startup path owns
	 * the call: the first guest function is what runs main(), and it reads
	 * the in-flight bytes straight out of the FC slots. Handing them to the
	 * worker instead would swallow the call, as it has no callback yet.
	 */
	if (!*hyperlight_dispatch_v2_slot())
		return;

	/* One call is in flight at a time: the host cannot issue another guest
	 * function until this pump returns, and the worker only parks again
	 * after reporting completion.
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

/* Must be called at worker-creation time; see the header for why. */
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

		/* Only a call that actually ran counts as complete. The pump
		 * reports it on its next return, at the latest when this
		 * thread parks below and the scheduler goes idle.
		 */
		if (hyperlight_dispatch_invoke_v2(fc, fc_len))
			hl_poll_call_done = 1;

		hl_poll_call_fc = NULL;
		hl_poll_call_fc_len = 0;
		uk_free(uk_alloc_get_default(), fc);
	}
}

/* Deliver the `poll` FunctionCall's first hlvecbytes parameter as the
 * completed-task batch: the host passes one binary frame holding every async
 * result ready for delivery, which deliver_batch() validates and routes.
 */
static void hyperlight_poll_deliver_arg(const __u8 *b, __sz len, __sz fc)
{
	__sz params, p0_pos, p0, vb, v;
	__u16 tf;
	__u32 slen;

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

/* Dispose of the guest function call that triggered this pump run: `poll`
 * carries the batch of completed host calls, any other name is an
 * application-level call for the dispatch worker to run on the scheduler.
 */
static void hl_poll_handle_fc(const __u8 *b, __sz len)
{
	__sz fc = hl_poll_fc_root(b, len);

	if (fc && hl_poll_fc_is_pump(b, len, fc))
		hyperlight_poll_deliver_arg(b, len, fc);
	else
		hl_poll_route_call(b, len);
}

/* The calling thread, if it can be parked in the guest scheduler: only while a
 * pump is driving it, and never the pump's own host thread, which returns
 * control to the host and would deadlock the pump if blocked.
 */
static struct uk_thread *hyperlight_poll_parkable_current(void)
{
	struct uk_thread *current = uk_thread_current();

	if (!hl_poll_host_thread || current == hl_poll_host_thread)
		return __NULL;

	return current;
}

int hyperlight_poll_halt(__nsec wakeup_time)
{
	struct uk_thread *current;

	/* The idle thread reaching a halt means the run queue has drained:
	 * record its deadline and hand the vCPU back to the host.
	 */
	if (hl_poll_host_thread &&
	    uk_thread_current() == hl_poll_idle_thread) {
		hl_poll_wakeup_time = wakeup_time;
		uk_sched_thread_switch(hl_poll_host_thread);
		return 1;
	}

	current = hyperlight_poll_parkable_current();
	if (!wakeup_time || !current)
		return 0;

	uk_thread_block_until(current, wakeup_time);
	uk_sched_yield();
	return 1;
}

int hyperlight_poll_park(void)
{
	struct uk_thread *current = hyperlight_poll_parkable_current();

	if (!current)
		return 0;

	uk_thread_block(current);
	uk_sched_yield();
	return 1;
}

/* Report the next-wakeup deadline to the host, using the same
 * {"name":...,"args":{...}} convention as the rest of the Hyperlight tooling.
 *
 *   ns: nanoseconds until the next timer fires (0 = none pending; 1 = re-poll
 *       immediately, a real timer is already due).
 *   call_done: a named guest function run by the dispatch worker has returned.
 *
 * Process exit is signalled separately by the application via __hl_exit.
 * Failures are non-fatal: the host falls back to an immediate re-poll.
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
	struct uk_thread *idle;
	__nsec wakeup_time;
	__nsec now;
	__u64 ns;
	unsigned long flags;
	int call_done;

	/* The const is dropped because uk_sched_thread_switch() needs a mutable
	 * handle; the idle thread object is legitimately mutable.
	 */
	idle = s ? (struct uk_thread *)uk_sched_idle_thread(s, 0) : __NULL;
	if (unlikely(!idle)) {
		/* No scheduler to drive: report "no timer" so the host does
		 * not busy-loop, and let __hl_exit signal completion.
		 */
		hyperlight_poll_report(0, 0);
		return;
	}

	/* Remember both ends of the context switch, arming the platform halt
	 * interception.
	 */
	hl_poll_host_thread = uk_thread_current();
	hl_poll_idle_thread = idle;

	/* The cooperative scheduler requires IRQs enabled: schedcoop_schedule()
	 * asserts this, and the idle thread we switch into calls it. The guest
	 * dispatch enters with IRQs disabled, so enable them for the scheduler
	 * run and restore the caller's state once idle hands control back.
	 */
	flags = uk_lcpu_save_irqf();
	uk_lcpu_enable_irq();

	/* Every guest function reaches the pump. */
	hl_poll_handle_fc(hyperlight_dispatch_current_fc_bytes(),
			  hyperlight_dispatch_current_fc_len());

#ifdef CONFIG_LIBHOSTSOCK
	/* A re-entry is our chance to observe socket I/O that arrived while the
	 * vCPU was yielded, so refresh readiness for all tracked host sockets:
	 * any thread parked on one is then woken and re-run below.
	 */
	hostsock_rescan_events();
#endif

	/* Switch directly into the idle thread, which drives every runnable
	 * thread cooperatively and, once the run queue drains, reaches its
	 * platform halt operation and switches control back to us.
	 *
	 * Entering via idle rather than yielding from the host thread
	 * guarantees the scheduler reaches idle even though the host thread
	 * stays "current": it is never offered to the run queue, so it cannot
	 * be re-selected ahead of idle.
	 */
	uk_sched_thread_switch(idle);

	/* Back from idle with IRQs disabled inside its critical section. */
	uk_lcpu_restore_irqf(flags);

	/* Snapshot and clear the shared state. */
	wakeup_time = hl_poll_wakeup_time;
	call_done = hl_poll_call_done;
	hl_poll_host_thread = NULL;
	hl_poll_idle_thread = NULL;
	hl_poll_wakeup_time = 0;
	hl_poll_call_done = 0;

	/* Translate the absolute deadline into a relative delay, reserving 0
	 * for "no pending timer". A real deadline can fall due while control
	 * switches from idle back here; report the minimum nonzero delay then,
	 * so the host re-polls at once instead of waiting for external I/O.
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
