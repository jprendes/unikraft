/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2026, Unikraft GmbH and The Unikraft Authors.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

/*
 * Cooperative "step" execution model for Hyperlight guests.
 * See include/hyperlight/step.h for the design.
 */

#include <string.h>
#include <errno.h>
#include <uk/arch/types.h>
#include <uk/arch/time.h>
#include <uk/plat/time.h>
#include <uk/alloc.h>
#include <uk/essentials.h>
#include <uk/init.h>
#include <uk/lcpu.h>
#include <uk/print.h>
#include <uk/sched.h>
#include <uk/sched_impl.h>
#include <uk/thread.h>
#if CONFIG_LIBPOSIX_PROCESS_SIGNAL
#include <uk/process.h>
#endif
#if CONFIG_LIBDEVFS
#include <vfscore/uio.h>
#include <devfs/device.h>
#endif /* CONFIG_LIBDEVFS */

#if CONFIG_LIBUKRANDOM
#include <uk/random.h>
#endif /* CONFIG_LIBUKRANDOM */

#include <hyperlight/console.h>
#include <hyperlight/dispatch.h>
#include <hyperlight/hcall.h>
#include <hyperlight/resolv.h>
#include <hyperlight/step.h>
#include <hyperlight/time.h>
#include <hyperlight/transport.h>

#ifdef CONFIG_LIBHOSTFS
/* Make the hostfs mounts match the host's after a snapshot restore.
 * Defined in lib/hostfs.
 */
extern void hostfs_resume(void);
extern void hostfs_resume_list(const char *mounts, __sz mounts_len);
#endif /* CONFIG_LIBHOSTFS */

#ifdef CONFIG_LIBHOSTSOCK
/* Re-poll every host-proxied socket and post readiness events, waking any
 * thread parked on one (a blocking recv/accept that returned EAGAIN and
 * yielded via uk_file_poll).  Defined in lib/hostsock.
 */
extern int hostsock_rescan_events(void);
/* Re-create the guest's host sockets after a snapshot restore. */
extern void hostsock_resume(void);
#endif /* CONFIG_LIBHOSTSOCK */

/* The relative delay reported when a deadline fell due while control was
 * switching back to the yield thread.  The protocol is "0 = no timer, N =
 * re-enter within N ns", so the smallest positive delay says "already due,
 * come straight back"; the host needs no matching constant.
 */
#define HL_STEP_DUE_NS 1ULL

/* What the guest tells the host, each as a named host function: the
 * protocol is the names and their typed arguments, nothing is encoded.
 *
 *   Yield(ns, flags, status, result)
 *                     every thread is blocked; the next timer fires in ns
 *                     (0: none).  Sent at every boundary, and once at boot
 *                     complete.  It also carries what the entry saw of the
 *                     call in flight, so a call costs no exit of its own:
 *                     HL_YIELD_STARTED, the reader took the call and it
 *                     is still running; HL_YIELD_DONE, it returned, with
 *                     status (0, or what the driver wrote to the device)
 *                     and result (what it returned; empty: nothing).
 *   DriverReady()     /dev/hlcall was opened: named calls are served.
 *   CallStarted()     the reader took a named call; sent on its own only
 *                     when no Yield follows (hyperlight_step_flush()).
 *   CallDone(status, result)
 *                     that call returned; likewise on its own only when no
 *                     Yield follows.
 *   CallRejected()    a named call had no reader, or did not fit.
 *
 * Exited(status), the process exit, is not the step model's: every
 * kernel on this platform sends it from the shutdown path (shutdown.c).
 *
 * After a restore, DriverReady and CallStarted are sent again if they
 * hold, so the new host learns them (see hl_resume()).  Every send is
 * best-effort: a host lacking one of these functions does not learn that
 * fact, and nothing else breaks.
 */
static void hl_emit(const char *event)
{
	__s32 out;

	(void)hl_hcall_int(event, NULL, 0, &out);
}

static void hl_emit_done(__s32 status, const __u8 *buf, __u64 len)
{
	struct hl_param p[2];
	__s32 out;

	p[0].type = HL_PV_HLINT;
	p[0].i32_val = status;
	p[1].type = HL_PV_HLVECBYTES;
	p[1].vec.ptr = buf;
	p[1].vec.len = (__u32)len;
	(void)hl_hcall_int("CallDone", p, 2, &out);
}

#define HL_YIELD_STARTED 1
#define HL_YIELD_DONE    2

/* What the entry saw of the call in flight, for its Yield. */
static int hl_start_pending;
static int hl_done_pending;
static __s32 hl_call_fail_status;      /* from the driver's write(); 0 = success */
static __u8 *hl_result_buf;            /* the result the driver wrote */
static __u64 hl_result_len;            /* 0 = none */

/* The call's report went out: clear it, and the result it carried. */
static void hl_step_forget_pending(void)
{
	if (hl_done_pending) {
		hl_result_len = 0;
		hl_call_fail_status = 0;
	}
	hl_done_pending = 0;
	hl_start_pending = 0;
}

/* A boundary: every thread is blocked and the next timer fires in @ns
 * (0: none), with what this entry saw of the call in flight.  The call's
 * start is reported only if it is still running: a return implies it.
 */
static void hl_emit_yield(__u64 ns)
{
	struct hl_param p[4];
	__s32 out, flags = 0;

	if (hl_done_pending)
		flags = HL_YIELD_DONE;
	else if (hl_start_pending)
		flags = HL_YIELD_STARTED;

	p[0].type = HL_PV_HLULONG;
	p[0].u64_val = ns;
	p[1].type = HL_PV_HLINT;
	p[1].i32_val = flags;
	p[2].type = HL_PV_HLINT;
	p[2].i32_val = hl_done_pending ? hl_call_fail_status : 0;
	p[3].type = HL_PV_HLVECBYTES;
	p[3].vec.ptr = hl_done_pending && hl_result_len ? hl_result_buf : (const __u8 *)"";
	p[3].vec.len = hl_done_pending ? (__u32)hl_result_len : 0;
	(void)hl_hcall_int("Yield", p, 4, &out);
	hl_step_forget_pending();
}

/* The guest function that drives the scheduler, and the one the host
 * uses in its place for the first entry after restoring this guest from a
 * snapshot.  Any other name is an application-level call for the
 * /dev/hlcall reader.
 */
static const char hl_step_fn_name[] = "step";
static const char hl_async_step_fn_name[] = "step_async";
static int hl_async_supported;
int hyperlight_execution_enabled;

struct hl_execution {
	struct hl_execution *next;
	__u64 id;
	unsigned int threads;
	int stopping;
};
static struct hl_execution *hl_executions;

#if CONFIG_LIBDEVFS
static struct hl_execution *hl_execution_find(__u64 id)
{
	struct hl_execution *execution;

	for (execution = hl_executions; execution; execution = execution->next)
		if (execution->id == id)
			return execution;
	return NULL;
}

static int hl_execution_stopping(void)
{
	struct hl_execution *execution =
		hl_execution_find(uk_thread_current()->hyperlight_execution);

	return execution && execution->stopping;
}
#endif

static int hl_execution_get(__u64 id)
{
	struct hl_execution *execution;

	for (execution = hl_executions; execution; execution = execution->next)
		if (execution->id == id) {
			execution->threads++;
			return 0;
		}
	execution = uk_malloc(uk_alloc_get_default(), sizeof(*execution));
	if (!execution)
		return -ENOMEM;
	*execution = (struct hl_execution) {
		.next = hl_executions, .id = id, .threads = 1
	};
	hl_executions = execution;
	return 0;
}

static int hl_execution_thread_init(struct uk_thread *child,
				    struct uk_thread *parent)
{
	child->hyperlight_execution = parent ? parent->hyperlight_execution : 0;
	return child->hyperlight_execution ?
		hl_execution_get(child->hyperlight_execution) : 0;
}

static void hl_execution_thread_term(struct uk_thread *thread)
{
	struct hl_execution **link = &hl_executions;
	struct hl_execution *execution;
	struct uk_thread *current = uk_thread_current();
	__u64 previous = current->hyperlight_execution;
	__s32 status;

	if (!thread->hyperlight_execution)
		return;
	while ((execution = *link) && execution->id != thread->hyperlight_execution)
		link = &execution->next;
	UK_ASSERT(execution && execution->threads);
	if (--execution->threads)
		return;
	current->hyperlight_execution = execution->id;
	if (hl_hcall_int("ExecutionDone", NULL, 0, &status) || status)
		UK_CRASH("cannot report execution completion\n");
	current->hyperlight_execution = previous;
	*link = execution->next;
	uk_free(uk_alloc_get_default(), execution);
}

UK_THREAD_INIT_PRIO_FLAGS(hl_execution_thread_init, hl_execution_thread_term, 0, 0);

static void hl_async_negotiate(void)
{
#if CONFIG_LIBDEVFS
	__u64 version = 0;

	hl_async_supported =
		hl_hcall_ulong("AsyncHostCallVersion", NULL, 0, &version) == 0 &&
		version == 1;
	/* Advertise that this kernel interrupts unfinished calls on resume. */
	if (hl_async_supported)
		(void)hl_hcall_ulong("AsyncHostCallInterruptVersion",
				    NULL, 0, &version);
#endif
}
static const char hl_resume_fn_name[] = "resume";

/* ── Pump state ──────────────────────────────────────────────────── */

/* The yield thread: the guest thread that is "current" whenever the VM
 * is halted.  Created at boot, parked until the first idle, and from
 * then on the thread every host entry runs on (see the header).
 */
static struct uk_thread *hl_yield_thread;

/* The deadline the scheduler went idle with at boot, reported by the
 * boot-complete halt: a workload that sleeps before anything else happens
 * is waiting on it.
 */
static __nsec hl_boot_wakeup;

/* Meaningful only while a pump is in flight. */
static int hl_pump_active;
static struct uk_thread *hl_pump_idle;
static __nsec hl_pump_wakeup;

/* ── Named-call queue (/dev/hlcall) ──────────────────────────────── */

/* Sized from the H2G buffers (hyperlight_dispatch_max_call) at init:
 * the host decides how large a call can be, the guest never guesses.
 */
static __u8 *hl_call_buf;
static __u64 hl_call_cap;
static __u64 hl_call_len;              /* 0 = nothing queued */
static struct uk_thread *hl_call_reader; /* thread blocked in read() */
static int hl_call_opened;             /* a driver has opened the device */
static __u64 hl_restores;              /* HLCALL_IOC_RESTORES */

/* The host's environment as the kernel last fetched it, and its version:
 * HLCALL_IOC_GETENV answers from here, with no host call, while the call
 * in flight carries the same version.  The host bumps it whenever the
 * environment changes, and on every restore.
 */
static __u64 hl_call_env_version;
static char *hl_env_cache;
static __u64 hl_env_cache_len;
static __u64 hl_env_cache_version;

/* The environment the kernel last could not take, by the version the
 * call carried and the size the host reported: reported once, not on
 * each named call that runs this, since the console is the workload's
 * output.  Under a nonzero version it is not fetched again either until
 * the host bumps the version, as it does for a new host (after a
 * restore) or a changed environment; a host that sends no version gets
 * a fetch every time, and a report when the size changes.
 */
static __u64 hl_env_failed_version;
static int hl_env_failed_len = -1;

/* An allocation failure is the kernel's own, not the environment's:
 * reported once, and the allocation retried every time.
 */
static int hl_env_nomem_reported;

/* The host's environment for @version, fetched with GetEnvVars only when
 * the version is not the one the copy was fetched under (0: always).
 * Returns 1 if it was fetched, 0 if the copy stood, -1 if it cannot be
 * had (no GetEnvVars on the host or the host call failed, no memory for
 * the copy, or hl_hcall_max_payload() bytes or more; under the nonzero
 * version that did not fit, -1 again with no host call);
 * *buf is NUL-terminated, *len without the final NUL.
 */
int hyperlight_step_env(__u64 version, const char **buf, __sz *len)
{
	__u64 cap = hl_hcall_max_payload();
	int n;

	if (version && version == hl_env_failed_version)
		return -1;
	if (!hl_env_cache) {
		hl_env_cache = cap ? uk_malloc(uk_alloc_get_default(), cap) : NULL;
		if (unlikely(!hl_env_cache)) {
			if (!hl_env_nomem_reported) {
				hl_env_nomem_reported = 1;
				uk_pr_err("step: no memory for the host environment\n");
			}
			return -1;
		}
	}
	if (version && version == hl_env_cache_version) {
		*buf = hl_env_cache;
		*len = hl_env_cache_len;
		return 0;
	}
	n = hl_call_get_env_vars(hl_env_cache, cap);
	if (n < 0) {
		/* No GetEnvVars on this host, or the call failed: no report,
		 * as a host may well serve no environment.
		 */
		hl_env_cache_version = 0;
		return -1;
	}
	if ((__u64)n >= cap) {
		if (version != hl_env_failed_version || n != hl_env_failed_len)
			uk_pr_err("step: host environment (%d bytes) does not fit\n",
				  n);
		hl_env_failed_version = version;
		hl_env_failed_len = n;
		hl_env_cache_version = 0;
		return -1;
	}
	hl_env_failed_version = 0;
	hl_env_failed_len = -1;
	hl_env_cache[n] = '\0';
	hl_env_cache_len = n;
	hl_env_cache_version = version;
	*buf = hl_env_cache;
	*len = hl_env_cache_len;
	return 1;
}

/* Queue a named FunctionCall for the device reader.
 *
 * A guest that never opens the device (a plain Linux binary run under the
 * pump) has nobody to serve the call; report it rejected at once so the
 * host fails the call instead of waiting forever for a reader.
 */
static void hl_route_call(const __u8 *fc, __u64 fc_len,
			  const struct hl_pc_call *call)
{
	if (!hl_call_opened) {
		uk_pr_warn("hyperlight: named call rejected, no /dev/hlcall reader\n");
		hl_emit("CallRejected");
		return;
	}
	if (unlikely(!hl_call_buf || fc_len > hl_call_cap)) {
		uk_pr_err("hyperlight: cannot queue a %llu-byte named call\n",
			  (unsigned long long)fc_len);
		hl_emit("CallRejected");
		return;
	}
	/* One call at a time: the host drives a named call to completion
	 * before issuing the next, so an unconsumed one here is a host bug.
	 */
	if (unlikely(hl_call_len)) {
		uk_pr_warn("hyperlight: named call dropped, previous one not yet consumed\n");
		return;
	}
	memcpy(hl_call_buf, fc, fc_len);
	hl_call_len = fc_len;
	hl_call_env_version = hl_pc_env_version(call);
	if (hl_call_reader)
		uk_thread_wake(hl_call_reader);
}

/* A call has been handed to the reader and not yet completed. */
static int hl_call_in_flight;

#if CONFIG_LIBDEVFS
/* The device's buffers, sized when it is first opened. */
/* What CallDone carries: hl_hcall_max_payload(). */
static __u64 hl_result_cap;
/* A HostCall reply, hl_reply_cap bytes. */
static __u8 *hl_reply_buf;
/* What a reply holds: hl_transport_payload_cap(). */
static __u64 hl_reply_cap;
/* A HostCall's name and args, hl_hcall_max_payload() bytes. */
static __u8 *hl_args_buf;

static int hlcall_open(struct device *dev __unused, int mode __unused)
{
	/* The buffers for results and host call replies are allocated when
	 * a driver first opens the device, once host calls are up and their
	 * payload size known.  Without them a result is refused (EMSGSIZE)
	 * and a host call fails (ENOMEM); a status alone still goes through.
	 */
	if (!hl_result_buf) {
		hl_result_cap = hl_hcall_max_payload();
		hl_result_buf = hl_result_cap ?
			uk_malloc(uk_alloc_get_default(), hl_result_cap) : NULL;
		if (unlikely(!hl_result_buf)) {
			uk_pr_err("hyperlight: no memory for a %llu-byte call result\n",
				  (unsigned long long)hl_result_cap);
			hl_result_cap = 0;
		}
	}
	if (!hl_reply_buf && hl_transport_payload_cap()) {
		hl_reply_cap = hl_transport_payload_cap();
		hl_reply_buf = uk_malloc(uk_alloc_get_default(), hl_reply_cap);
		if (unlikely(!hl_reply_buf))
			uk_pr_err("hyperlight: no memory for a %llu-byte host call reply\n",
				  (unsigned long long)hl_reply_cap);
	}
	if (!hl_args_buf && hl_hcall_max_payload()) {
		hl_args_buf = uk_malloc(uk_alloc_get_default(),
					hl_hcall_max_payload());
		if (unlikely(!hl_args_buf))
			uk_pr_err("hyperlight: no memory for a %llu-byte host call\n",
				  (unsigned long long)hl_hcall_max_payload());
	}
	hl_call_opened = 1;
	hl_emit("DriverReady");
	return 0;
}

/* Block until a named call is queued, then hand its FunctionCall bytes
 * to the caller.  Coming back for the next call means the previous one
 * completed; the pump reports that on its next return.
 */
static int hlcall_read(struct device *dev __unused, struct uio *uio,
		       int flags __unused)
{
	__u8 *buf;
	__u64 cap, n;

	if (unlikely(!uio->uio_iov || uio->uio_iovcnt < 1))
		return EINVAL;
	if (hl_call_reader && hl_call_reader != uk_thread_current())
		return EBUSY;
	buf = uio->uio_iov->iov_base;
	cap = uio->uio_iov->iov_len;

	/* Reported with the entry's Yield (hl_emit_yield()). */
	if (hl_call_in_flight) {
		hl_call_in_flight = 0;
		hl_done_pending = 1;
	}

	while (!hl_call_len) {
		hl_call_reader = uk_thread_current();
		uk_thread_block(hl_call_reader);
		uk_sched_yield();
	}
	hl_call_reader = NULL;

	n = MIN(hl_call_len, cap);
	memcpy(buf, hl_call_buf, n);
	hl_call_len = 0;
	hl_call_in_flight = 1;
	hl_start_pending = 1;
	uio->uio_resid -= (ssize_t)n;

	return 0;
}

/* The driver reports how the call it is serving went: a 32-bit status,
 * 0 for success, optionally followed by what the call returned.  Written
 * before the next read(), which reports the call done with the status
 * and the result, one host call (CallDone).  The kernel
 * interprets neither.  A result travels as a host call's parameter, so it
 * is at most hl_hcall_max_payload() bytes; a larger one is refused
 * (EMSGSIZE) rather than lost on the way.
 */
static int hlcall_write(struct device *dev __unused, struct uio *uio,
			int flags __unused)
{
	__u8 *st;
	__u64 total = 0, pos = 0;
	__s32 status;
	int i;

	if (unlikely(!uio->uio_iov || uio->uio_iovcnt < 1))
		return EINVAL;
	if (!hl_call_in_flight)
		return EPERM;
	for (i = 0; i < uio->uio_iovcnt; i++)
		total += uio->uio_iov[i].iov_len;
	if (unlikely(total < sizeof(status)))
		return EINVAL;
	if (total - sizeof(status) > hl_result_cap)
		return EMSGSIZE;

	/* The status, then the result, gathered from however many iovecs
	 * the driver wrote them with.
	 */
	st = (__u8 *)&status;
	for (i = 0; i < uio->uio_iovcnt; i++) {
		const __u8 *b = uio->uio_iov[i].iov_base;
		__u64 n = uio->uio_iov[i].iov_len;

		while (n) {
			__u64 k;

			if (pos < sizeof(status)) {
				k = MIN(n, sizeof(status) - pos);
				memcpy(st + pos, b, k);
			} else {
				k = n;
				memcpy(hl_result_buf + (pos - sizeof(status)), b, k);
			}
			pos += k;
			b += k;
			n -= k;
		}
	}
	hl_call_fail_status = status;
	hl_result_len = total - sizeof(status);
	uio->uio_resid -= (ssize_t)total;
	return 0;
}

struct hl_async_wait {
	struct hl_async_wait *next;
	struct uk_thread *thread;
	__u64 id;
	__u8 *out;
	__u64 cap, len;
	int done;
	int error;
};

static struct hl_async_wait *hl_async_waiters;

static void hl_async_remove(struct hl_async_wait *wait)
{
	struct hl_async_wait **link = &hl_async_waiters;

	while (*link && *link != wait)
		link = &(*link)->next;
	if (*link)
		*link = wait->next;
	uk_free(uk_alloc_get_default(), wait);
}

static void hl_async_cancel(__u64 id)
{
	struct hl_param p = { .type = HL_PV_HLULONG, .u64_val = id };
	__s32 out;

	if (hl_hcall_int("CancelAsyncHostCall", &p, 1, &out) < 0)
		uk_pr_err("hyperlight: failed to cancel async host call\n");
}

static void hl_async_cancel_execution(__u64 id)
{
	struct hl_async_wait *wait;
	struct uk_thread *current = uk_thread_current();
	__u64 previous = current->hyperlight_execution;

	current->hyperlight_execution = id;
	for (wait = hl_async_waiters; wait; wait = wait->next) {
		if (wait->thread->hyperlight_execution != id || wait->done)
			continue;
		hl_async_cancel(wait->id);
		wait->error = ECANCELED;
		wait->done = 1;
		uk_thread_wake(wait->thread);
	}
	current->hyperlight_execution = previous;
}

/* A killed thread must never receive a reply into its released stack. */
static void hl_async_thread_term(struct uk_thread *thread)
{
	struct hl_async_wait *w = hl_async_waiters, *next;
	struct uk_thread *current = uk_thread_current();
	__u64 previous = current->hyperlight_execution;

	current->hyperlight_execution = thread->hyperlight_execution;
	while (w) {
		next = w->next;
		if (w->thread == thread) {
			if (!w->done)
				hl_async_cancel(w->id);
			hl_async_remove(w);
		}
		w = next;
	}
	current->hyperlight_execution = previous;
}

UK_THREAD_INIT_PRIO_FLAGS(0, hl_async_thread_term, 0, 0);

static __u32 hl_async_u32(const __u8 *p)
{
	return (__u32)p[0] | ((__u32)p[1] << 8) |
	       ((__u32)p[2] << 16) | ((__u32)p[3] << 24);
}

static __u64 hl_async_u64(const __u8 *p)
{
	return (__u64)hl_async_u32(p) | ((__u64)hl_async_u32(p + 4) << 32);
}

static int hl_async_wait_for(__u64 id, __u8 *out, __u64 cap, __u64 *len)
{
	struct hl_async_wait *wait;
	int error;

	if (hl_execution_stopping()) {
		hl_async_cancel(id);
		return ECANCELED;
	}
	if (!hl_async_supported || !id)
		return EPROTO;
	wait = uk_malloc(uk_alloc_get_default(), sizeof(*wait));
	if (!wait) {
		hl_async_cancel(id);
		return ENOMEM;
	}
	*wait = (struct hl_async_wait) {
		.next = hl_async_waiters,
		.thread = uk_thread_current(),
		.id = id,
		.out = out,
		.cap = cap,
	};
	hl_async_waiters = wait;
	while (!wait->done) {
		if (uk_thread_is_interrupted(wait->thread)) {
			hl_async_cancel(wait->id);
			hl_async_remove(wait);
			return EINTR;
		}
		uk_thread_block(wait->thread);
		uk_sched_yield();
	}
	*len = wait->len;
	error = wait->error ? wait->error : (wait->len > cap ? ENOBUFS : 0);
	hl_async_remove(wait);
	return error;
}

int hl_hcall_async_int(const char *name, const struct hl_param *params,
		      int nparams, __s32 *result)
{
	__u8 reply[9];
	__sz len;
	__u64 completed;
	int error;

	if (hl_execution_stopping())
		return -ECANCELED;
	if (hl_hcall_vecbytes(name, params, nparams, reply, sizeof(reply),
			      &len) < 0)
		return -EIO;
	if (len && reply[0] == 2) {
		if (len != 9)
			return -EPROTO;
		error = hl_async_wait_for(hl_async_u64(reply + 1), reply,
					 sizeof(reply), &completed);
		if (error)
			return -error;
		len = completed;
	}
	if (len != 5 || reply[0] != 0)
		return -EPROTO;
	*result = (__s32)hl_async_u32(reply + 1);
	return 0;
}

static void hl_async_finish(struct hl_async_wait *wait, const __u8 *reply,
			    __u64 len)
{
	wait->len = len;
	if (len <= wait->cap)
		memcpy(wait->out, reply, len);
	wait->done = 1;
	uk_thread_wake(wait->thread);
}

/* Wake only after socket/mount/clock restoration and never cancel an old ID
 * against the new host's request namespace.
 */
static void hl_async_restore(void)
{
	struct hl_async_wait *wait;

	for (wait = hl_async_waiters; wait; wait = wait->next) {
		/* Even a delivered waiter must leave the old ID namespace. */
		wait->id = 0;
		if (wait->done)
			continue;
		wait->error = EINTR;
		wait->len = 0;
		wait->done = 1;
		uk_thread_wake(wait->thread);
	}
}

/* Validate everything before publishing any completion. */
static int hl_async_deliver(const __u8 *buf, __u64 len)
{
	struct hl_async_wait *waiters[64], *w;
	const __u8 *replies[64];
	__u32 lengths[64], count, i, j, n;
	__u64 id, pos = 8;

	if (len < 8 || len > hyperlight_dispatch_max_call() ||
	    hl_async_u32(buf) != 1)
		return -1;
	count = hl_async_u32(buf + 4);
	if (!count || count > 64)
		return -1;
	for (i = 0; i < count; i++) {
		if (len - pos < 12)
			return -1;
		id = hl_async_u64(buf + pos);
		n = hl_async_u32(buf + pos + 8);
		pos += 12;
		if (!n || n > hl_hcall_max_payload() || n > len - pos ||
		    buf[pos] > 1)
			return -1;
		for (w = hl_async_waiters; w && w->id != id; w = w->next)
			;
		if (!w || w->done)
			return -1;
		for (j = 0; j < i; j++)
			if (waiters[j] == w)
				return -1;
		waiters[i] = w;
		replies[i] = buf + pos;
		lengths[i] = n;
		pos += n;
	}
	if (pos != len)
		return -1;
	for (i = 0; i < count; i++) {
		w = waiters[i];
		hl_async_finish(w, replies[i], lengths[i]);
	}
	return 0;
}

/* The decoded Postcard call carries one contiguous completion batch. */
static int hl_async_step(const struct hl_pc_call *call)
{
	if (call->np != 1 || call->params[0].type != HL_PV_HLVECBYTES)
		return -1;
	return hl_async_deliver(call->params[0].vec.ptr,
				call->params[0].vec.len);
}

/* HLCALL_IOC_HOSTCALL: HostCall(name, args) on the host, the reply into
 * the driver's buffer.  See step.h.
 */
static int hl_host_call(struct hlcall_hostcall *arg)
{
	/* Read once: what is checked is what is used, whatever the driver's
	 * struct holds by the time the copies below are made.
	 */
	struct hlcall_hostcall hc = *arg;
	struct hl_param p[2];
	__u64 max = hl_hcall_max_payload();
	__sz len = 0;

	/* An empty name is the host's to interpret (the library lists its
	 * functions for it); a missing one is not.
	 */
	if (unlikely(!hc.name || !hc.out || (hc.args_len && !hc.args)))
		return EINVAL;
	if (!hl_call_in_flight && !uk_thread_current()->hyperlight_execution)
		return EPERM;
	/* Both travel in one host call: together at most its payload.  The
	 * encoder sizes them in 32 bits, so this also keeps it from
	 * wrapping.
	 */
	if (hc.name_len > max || hc.args_len > max ||
	    hc.name_len + hc.args_len > max)
		return E2BIG;
	if (unlikely(!hl_reply_buf || !hl_args_buf))
		return ENOMEM;
	/* The name and args are copied in first, as the reply is copied out
	 * last: the name is checked on the copy, so a name that is not UTF-8
	 * fails with EILSEQ (hl_hcall_vecbytes() would refuse it too, but
	 * as EIO), and the reply arrives whole before the driver's buffer,
	 * which may be too small for it (ENOBUFS, with its length), is
	 * written. This single-vCPU path does not schedule until after the
	 * reply is copied out of these shared buffers.
	 */
	memcpy(hl_args_buf, hc.name, hc.name_len);
	if (!hl_utf8_valid(hl_args_buf, hc.name_len))
		return EILSEQ;
	if (hc.args_len)
		memcpy(hl_args_buf + hc.name_len, hc.args, hc.args_len);
	p[0].type = HL_PV_HLSTRING;
	p[0].str.ptr = (const char *)hl_args_buf;
	p[0].str.len = (__u32)hc.name_len;
	p[1].type = HL_PV_HLVECBYTES;
	p[1].vec.ptr = hl_args_buf + hc.name_len;
	p[1].vec.len = (__u32)hc.args_len;
	/* Into a kernel buffer as large as any reply (a G2H reply half), so
	 * the reply arrives whole, and only then into the driver's, which
	 * may be too small for it (ENOBUFS, with its length, below).
	 */
	if (hl_hcall_vecbytes("HostCall", p, 2, hl_reply_buf, hl_reply_cap,
			      &len) < 0)
		return EIO;
	if (len && hl_reply_buf[0] == 2) {
		if (len != 9)
			return EPROTO;
		return hl_async_wait_for(hl_async_u64(hl_reply_buf + 1),
					 hc.out, hc.out_cap, &arg->out_len);
	}
	arg->out_len = len;
	if (len > hc.out_cap)
		return ENOBUFS;
	memcpy(hc.out, hl_reply_buf, len);
	return 0;
}

/* HLCALL_IOC_MAXLEN: tell the driver how big a call can get, so it sizes
 * its buffers from the host's number rather than a guess of its own.
 * HLCALL_IOC_GETENV: hand it the host's environment (see step.h).
 * HLCALL_IOC_RESTORES: how many times the guest was restored (step.h).
 */
static int hl_command_io(struct hl_command_io *io)
{
	struct hl_param p[2];
	__u8 reply[4105];
	__sz len;
	__u64 completed;
	int error;

	if (!uk_thread_current()->hyperlight_execution ||
	    io->stream > 2 || io->len > 4096 || (io->len && !io->buf))
		return EINVAL;
	if (hl_execution_stopping()) {
		io->done = 0;
		return io->stream ? EPIPE : 0;
	}
	p[0].type = HL_PV_HLULONG;
	p[0].u64_val = io->stream;
	p[1].type = HL_PV_HLVECBYTES;
	p[1].vec.ptr = io->stream ? io->buf : (const __u8 *)"";
	p[1].vec.len = io->stream ? io->len : 0;
	if (hl_hcall_vecbytes("CommandIo", p, 2, reply, sizeof(reply), &len))
		return EIO;
	if (len == 9 && reply[0] == 2) {
		error = hl_async_wait_for(hl_async_u64(reply + 1), reply,
					 sizeof(reply), &completed);
		if (error == ECANCELED && hl_execution_stopping()) {
			io->done = 0;
			return io->stream ? EPIPE : 0;
		}
		if (error)
			return error;
		len = completed;
	}
	if (len == 5 && reply[0] == 1)
		return fb_u32(reply, 1);
	if (!len || reply[0] != 0 || (!io->stream && len - 1 > io->len))
		return EPROTO;
	if (!io->stream && len > 1)
		memcpy(io->buf, reply + 1, len - 1);
	io->done = io->stream ? io->len : len - 1;
	return 0;
}

static int hlcall_ioctl(struct device *dev __unused, unsigned long cmd,
			void *arg)
{
	if (unlikely(!arg))
		return EINVAL;

	switch (cmd) {
	case HLCALL_IOC_EXECUTION_KILL: {
		struct hl_execution *execution;

		if (!hyperlight_execution_enabled || !*(__u64 *)arg ||
		    uk_thread_current()->hyperlight_execution)
			return EINVAL;
#if CONFIG_LIBPOSIX_PROCESS_SIGNAL
		execution = hl_execution_find(*(__u64 *)arg);
		if (!execution)
			return 0;
		execution->stopping = 1;
		hl_async_cancel_execution(execution->id);
		return -uk_process_kill_execution(*(__u64 *)arg);
#else
		return EOPNOTSUPP;
#endif
	}
	case HLCALL_IOC_COMMAND_IO:
		return hl_command_io(arg);
	case HLCALL_IOC_COMMAND_EVENT: {
		struct hl_command_event *event = arg;
		struct hl_param p[2] = {
			{ .type = HL_PV_HLINT, .i32_val = event->kind },
			{ .type = HL_PV_HLINT, .i32_val = event->value }
		};
		__s32 status;

		if (!uk_thread_current()->hyperlight_execution)
			return EPERM;
		return hl_hcall_int("CommandEvent", p, 2, &status) ? EIO : status;
	}
	case HLCALL_IOC_EXECUTION:
		if (!hyperlight_execution_enabled || !*(__u64 *)arg ||
		    uk_thread_current()->hyperlight_execution)
			return EINVAL;
		if (hl_execution_get(*(__u64 *)arg))
			return ENOMEM;
		uk_thread_current()->hyperlight_execution = *(__u64 *)arg;
		return 0;
	case HLCALL_IOC_COMMAND_DRIVER: {
		__u64 version = 0;

		if (hl_hcall_ulong("CommandDriverVersion", NULL, 0, &version) ||
		    version != 2)
			return EOPNOTSUPP;
		hyperlight_execution_enabled = 1;
		*(__u64 *)arg = 2;
		return 0;
	}
	case HLCALL_IOC_MAXLEN:
		*(__u64 *)arg = hl_call_cap;
		return 0;
	case HLCALL_IOC_HOSTCALL:
		return hl_host_call(arg);
	case HLCALL_IOC_RESTORES:
		*(__u64 *)arg = hl_restores;
		return 0;
	case HLCALL_IOC_GETENV: {
		struct hlcall_env *env = arg;
		const char *buf;
		__sz len;

		if (unlikely(!env->buf))
			return EINVAL;
		if (hyperlight_step_env(hl_call_env_version, &buf, &len) < 0)
			return EIO;
		if (len >= env->cap)
			return ENOBUFS;
		memcpy(env->buf, buf, len + 1);
		env->len = len;
		return 0;
	}
	default:
		return ENOTTY;
	}
}

static struct devops hlcall_devops = {
	.open  = hlcall_open,
	.close = dev_noop_close,
	.read  = hlcall_read,
	.write = hlcall_write,
	.ioctl = hlcall_ioctl,
};

static struct driver hlcall_driver = {
	.name   = "hlcall",
	.devops = &hlcall_devops,
	.devsz  = 0,
};

static int hlcall_register(struct uk_init_ctx *ictx __unused)
{
	int rc;

	rc = device_create(&hlcall_driver, "hlcall",
			   D_CHR | D_IOCTL_UNLOCKED | D_READ_UNLOCKED, NULL);
	if (unlikely(rc)) {
		uk_pr_err("hyperlight: failed to register /dev/hlcall: %d\n",
			  rc);
		return -rc;
	}
	return 0;
}

devfs_initcall(hlcall_register);
#endif /* CONFIG_LIBDEVFS */

/* What a Yield reports for a monotonic deadline: the time left until it
 * (HL_STEP_DUE_NS once it has passed), or 0 for none.
 */
static __u64 hl_ns_until(__nsec wakeup)
{
	__nsec now;

	if (!wakeup)
		return 0;
	now = ukplat_monotonic_clock();
	return (wakeup > now) ? (__u64)(wakeup - now) : HL_STEP_DUE_NS;
}

static void hl_execution_timers(void)
{
	struct uk_thread *thread;
	__u64 records[128];
	unsigned int count = 0;
	__s32 status;

	if (!hyperlight_execution_enabled)
		return;
	UK_TAILQ_FOREACH(thread, &uk_sched_current()->thread_list, thread_list) {
		if (!thread->hyperlight_execution || thread->wakeup_time <= 0 ||
		    uk_thread_is_exited(thread))
			continue;
		records[count++] = thread->hyperlight_execution;
		records[count++] = hl_ns_until(thread->wakeup_time);
		if (count == ARRAY_SIZE(records)) {
			struct hl_param p = { .type = HL_PV_HLVECBYTES,
				.vec = { .ptr = (const __u8 *)records,
					 .len = count * sizeof(*records) } };
			if (hl_hcall_int("ExecutionTimers", &p, 1, &status) || status)
				UK_CRASH("cannot report execution timers\n");
			count = 0;
		}
	}
	if (count) {
		struct hl_param p = { .type = HL_PV_HLVECBYTES,
			.vec = { .ptr = (const __u8 *)records,
				 .len = count * sizeof(*records) } };
		if (hl_hcall_int("ExecutionTimers", &p, 1, &status) || status)
			UK_CRASH("cannot report execution timers\n");
	}
}

/* ── Yield thread ────────────────────────────────────────────────── */

static __noreturn void hl_yield_thread_fn(void)
{
	/* Park until the scheduler first goes idle (boot complete). */
	uk_thread_block(uk_thread_current());
	uk_sched_yield();

	/* Tell the host this guest runs the step model, then hand the VM
	 * over.  (A driver that opened /dev/hlcall has already said so.)
	 * Every later entry comes back through hyperlight_dispatch_function
	 * on this thread and reaches the pump.
	 */
	hl_emit_yield(hl_ns_until(hl_boot_wakeup));
	hyperlight_halt_boot_done();
}

static int hl_yield_thread_create(struct uk_init_ctx *ictx __unused)
{
	struct uk_sched *s = uk_sched_current();

	if (!s) {
		uk_pr_debug("hyperlight: no scheduler, step model disabled\n");
		return 0;
	}

	/* The named-call queue holds one call of the largest size the host
	 * can send.  Without it every named call is rejected; the step
	 * model itself still works, so this is not fatal.
	 */
	hl_call_cap = hyperlight_dispatch_max_call();
	hl_call_buf = hl_call_cap ?
		uk_malloc(uk_alloc_get_default(), hl_call_cap) : NULL;
	if (unlikely(!hl_call_buf)) {
		uk_pr_err("hyperlight: no memory for the %llu-byte call queue\n",
			  (unsigned long long)hl_call_cap);
		hl_call_cap = 0;
	}

	/* Default stack: it only ever runs the park above; once the VM has
	 * halted on it, every entry runs on the dispatch stack instead.
	 */
	hl_yield_thread = uk_sched_thread_create_fn0(s, hl_yield_thread_fn,
						    0, 0, false, false,
						    "hl-yield", NULL, NULL);
	if (unlikely(!hl_yield_thread)) {
		uk_pr_err("hyperlight: failed to create the yield thread; "
			  "the step model is unavailable\n");
		return 0;
	}
	/* A driverless entry can wait on networking before the first idle. */
	hl_async_negotiate();
	return 0;
}

uk_late_initcall(hl_yield_thread_create, 0x0);

/* ── Pump ────────────────────────────────────────────────────────── */

/* Read a little-endian field of @n bytes from the resume state. */
static int hl_state_take(const __u8 **p, const __u8 *end, void *out, __sz n)
{
	if ((__sz)(end - *p) < n)
		return -1;
	memcpy(out, *p, n);
	*p += n;
	return 0;
}

/* What a restored guest needs from its new host, in one host call
 * rather than one each: GetResumeState's reply is the wall clock (u64
 * ns), then the mount table and the resolver configuration, each a u32
 * length and its bytes, as GetMounts and GetResolvConf would answer.
 * -1 if the host has no GetResumeState, or the reply is malformed.
 */
static int hl_resume_state(void)
{
	__sz cap = hl_hcall_max_payload(), len = 0;
	const __u8 *p, *end, *mounts, *resolv;
	__u32 mounts_len, resolv_len;
	__u64 wall_ns;
	__u8 *buf;
	int rc = -1;

	buf = cap ? uk_malloc(uk_alloc_get_default(), cap) : NULL;
	if (unlikely(!buf))
		return -1;
	if (hl_hcall_vecbytes("GetResumeState", NULL, 0, buf, cap, &len) < 0)
		goto out;
	p = buf;
	end = buf + len;
	if (hl_state_take(&p, end, &wall_ns, sizeof(wall_ns)) < 0 ||
	    hl_state_take(&p, end, &mounts_len, sizeof(mounts_len)) < 0 ||
	    (__sz)(end - p) < mounts_len)
		goto out;
	mounts = p;
	p += mounts_len;
	if (hl_state_take(&p, end, &resolv_len, sizeof(resolv_len)) < 0 ||
	    (__sz)(end - p) < resolv_len)
		goto out;
	resolv = p;

#ifdef CONFIG_LIBHOSTFS
	hostfs_resume_list((const char *)mounts, mounts_len);
#else /* !CONFIG_LIBHOSTFS */
	(void)mounts;
#endif /* !CONFIG_LIBHOSTFS */
#ifdef CONFIG_LIBHOSTSOCK
	hostsock_resume();
#endif /* CONFIG_LIBHOSTSOCK */
	/* The wall clock stopped with the snapshot; the host's did not. */
	hyperlight_time_resync_to(wall_ns);
	/* The snapshot carries the resolver configuration of the machine
	 * that took it; this host may have another for the guest.
	 */
	hyperlight_resolv_apply_text((const char *)resolv, resolv_len);
	rc = 0;
out:
	uk_free(uk_alloc_get_default(), buf);
	return rc;
}

/* The host has just restored this guest from a snapshot.  These are put
 * right here, before anything else runs:
 *
 *   the console asks the new host afresh for HostWrite and HostWriteErr,
 *   which the snapshot's may have lacked (hyperlight_console_resume()),
 *   first, so the reports of what follows take the right way out;
 *
 *   the restore count goes up, which drivers read (HLCALL_IOC_RESTORES)
 *   to reseed what their runtimes seeded before the snapshot;
 *
 *   the CSPRNG is reseeded: its state lives in guest memory, so without
 *   this every clone of one snapshot would draw the same "random" bytes
 *   (the same UUIDs, tokens and TLS nonces) until the periodic reseed
 *   happened to fire;
 *
 *   the hostfs mounts are made to match the host's: the mount table is
 *   guest memory and describes the snapshot's mounts, not the ones this
 *   host serves, which may be more, fewer or others (see
 *   hostfs_resume());
 *
 *   the host sockets are re-established: they belonged to the process
 *   that took the snapshot, so listeners are opened and bound again and
 *   connections are declared dead (see hostsock_resume());
 *
 *   the wall clock is re-anchored on the host's: the guest's kept
 *   counting from the snapshot, not through the time spent on disk;
 *
 *   the resolver configuration is fetched again: the snapshot carries
 *   the file of the machine that took it (see resolv.c).
 */
static void hl_resume(void)
{
#if CONFIG_LIBUKRANDOM
	int rc;
#endif /* CONFIG_LIBUKRANDOM */

	hl_async_negotiate();
	hyperlight_console_resume();
	hl_restores++;
#if CONFIG_LIBUKRANDOM
	rc = uk_random_reseed();
	if (unlikely(rc))
		uk_pr_err("hyperlight: CSPRNG reseed after restore failed: %d\n",
			  rc);
#endif /* CONFIG_LIBUKRANDOM */
	/* One host call for the mounts, the clock and the resolver; a host
	 * without it answers each on its own.
	 */
	if (hl_resume_state() < 0) {
#ifdef CONFIG_LIBHOSTFS
		hostfs_resume();
#endif /* CONFIG_LIBHOSTFS */
#ifdef CONFIG_LIBHOSTSOCK
		hostsock_resume();
#endif /* CONFIG_LIBHOSTSOCK */
		hyperlight_time_resync();
		hyperlight_resolv_apply();
	}
#if CONFIG_LIBDEVFS
	hl_async_restore();
#endif
	/* The new host has not heard these yet. */
	if (hl_call_opened)
		hl_emit("DriverReady");
	if (hl_call_in_flight)
		hl_emit("CallStarted");
}

int hyperlight_step_halt(__nsec wakeup_time)
{
	struct uk_thread *cur = uk_thread_current();

	/* A pump is driving the scheduler and its idle thread reached a
	 * halt: the run queue has drained.  Record the deadline and hand
	 * the vCPU back; the next pump switches into us again right here.
	 */
	if (hl_pump_active && cur == hl_pump_idle) {
		hl_pump_wakeup = wakeup_time;
		uk_sched_thread_switch(hl_yield_thread);
		return 1;
	}

	/* Boot: the first idle means the workload has started and has
	 * nothing more to do until the host drives it.  Wake the parked
	 * yield thread; the idle loop yields to it and it halts the VM.
	 * (uk_thread_is_blocked() is not used: upstream's macro is
	 * mis-parenthesised and always false.)
	 */
	if (!hyperlight_booted() && hl_yield_thread &&
	    !uk_thread_is_runnable(hl_yield_thread)) {
		hl_boot_wakeup = wakeup_time;
		uk_thread_wake(hl_yield_thread);
		return 1;
	}

	return 0;
}

void hyperlight_step_pump(const __u8 *fc, __u64 fc_len,
			  const struct hl_pc_call *call)
{
	struct uk_sched *s = uk_sched_current();
	struct uk_thread *idle;
	unsigned long flags;
	__nsec wakeup;

	/* The const is dropped because uk_sched_thread_switch() needs a
	 * mutable handle; the idle thread object is legitimately mutable.
	 */
	idle = s ? (struct uk_thread *)uk_sched_idle_thread(s, 0) : NULL;
	if (unlikely(!idle || !hl_yield_thread ||
		     uk_thread_current() != hl_yield_thread)) {
		/* Nothing left to drive: no scheduler, or the VM last halted
		 * on some other thread -- the shutdown path after the workload
		 * exited during boot, before the yield thread ever ran.  Say
		 * nothing: a step that ends without a report is how the host
		 * learns the guest is gone, and reporting "idle" here would
		 * have it wait on a dead guest forever.
		 */
		uk_pr_warn("hyperlight: step pump entered without a "
			   "schedulable guest\n");
		return;
	}

	if (hl_pc_name_is(call, hl_async_step_fn_name)) {
#if CONFIG_LIBDEVFS
		if (!hl_async_supported || hl_async_step(call) < 0) {
			uk_pr_err("hyperlight: malformed async completion batch\n");
			return;
		}
#else
		uk_pr_err("hyperlight: async host calls require devfs\n");
		return;
#endif
	} else if (hl_pc_name_is(call, hl_resume_fn_name))
		hl_resume();
	else if (!hl_pc_name_is(call, hl_step_fn_name))
		hl_route_call(fc, fc_len, call);

	hl_pump_active = 1;
	hl_pump_idle = idle;
	hl_pump_wakeup = 0;

	/* The cooperative scheduler requires IRQs enabled (schedcoop asserts
	 * it), and the dispatch entry runs with them disabled: enable them
	 * for the scheduler run and put the caller's state back after idle
	 * hands control back.
	 */
	flags = uk_lcpu_save_irqf();
	uk_lcpu_enable_irq();

#ifdef CONFIG_LIBHOSTSOCK
	/* A re-entry is the chance to observe socket I/O that arrived while
	 * the vCPU was yielded: refresh readiness on every tracked socket so
	 * a thread parked on one is woken and run below.
	 */
	hostsock_rescan_events();
#endif /* CONFIG_LIBHOSTSOCK */

	/* Switch straight into the idle thread.  It runs every runnable
	 * thread and, once the run queue drains, reaches its platform halt,
	 * which switches control back here.  Entering via idle rather than
	 * yielding guarantees the scheduler reaches idle even though this
	 * thread stays "current": it is never offered to the run queue.
	 */
	uk_sched_thread_switch(idle);

	uk_lcpu_restore_irqf(flags);

	wakeup = hl_pump_wakeup;
	hl_pump_active = 0;
	hl_pump_idle = NULL;
	hl_pump_wakeup = 0;

	hl_execution_timers();
	hl_emit_yield(hl_ns_until(wakeup));
}

/* Report the call's start or return on its own: for a path that ends the
 * entry without a Yield (the process exiting).
 */
void hyperlight_step_flush(void)
{
	if (hl_done_pending)
		hl_emit_done(hl_call_fail_status, hl_result_buf, hl_result_len);
	else if (hl_start_pending)
		hl_emit("CallStarted");
	hl_step_forget_pending();
}
