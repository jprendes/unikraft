/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2024, Unikraft GmbH and The Unikraft Authors.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

/*
 * Hyperlight host calls use Postcard control data over the G2H virtqueue.
 * Byte parameters and results follow control data in parameter order;
 * the transport header carries both the control and total payload lengths.
 */

#include <string.h>
#include <uk/alloc.h>
#include <uk/arch/limits.h>
#include <uk/assert.h>
#include <uk/essentials.h>
#include <uk/plat/spinlock.h>
#include <uk/print.h>

#include <hyperlight/hcall.h>
#include <hyperlight/postcard.h>
#include <hyperlight/transport.h>
#include <hyperlight/step.h>
#include <uk/thread.h>

/* The transport has one request/reply buffer pair. Disable preemption
 * while using it, and reject reentrant calls (including kernel logging).
 */
static __spinlock g_hcall_lock = UKARCH_SPINLOCK_INITIALIZER();
static int g_hcall_busy;
static __u64 g_execution;

static int hcall_enter(unsigned long *irqf)
{
	ukplat_spin_lock_irqsave(&g_hcall_lock, *irqf);
	if (g_hcall_busy) {
		ukplat_spin_unlock_irqrestore(&g_hcall_lock, *irqf);
		return -1;
	}
	g_hcall_busy = 1;
	return 0;
}

static void hcall_exit(unsigned long irqf)
{
	g_hcall_busy = 0;
	ukplat_spin_unlock_irqrestore(&g_hcall_lock, irqf);
}

void hl_hcall_init(void)
{
	if (hl_transport_init() < 0)
		UK_CRASH("hcall: cannot attach to the host's virtqueues\n");
	if (!hl_hcall_max_payload())
		UK_CRASH("hcall: the G2H pool is too small; give it at least 3 pages\n");
}

int hl_hcall_ready(void)
{
	return hl_transport_ready();
}

/* Keep the existing payload budget: room for the function name, control
 * fields and other parameters (including a hostfs path of up to 1024 bytes).
 */
#define HL_HCALL_FRAMING 4096

__u64 hl_hcall_max_payload(void)
{
	__u64 cap = hl_transport_payload_cap();

	return cap > HL_HCALL_FRAMING ? cap - HL_HCALL_FRAMING : 0;
}

/* Copies run with interrupts off. Fault in demand-paged program buffers
 * before taking the lock; CoW faults can be served while it is held.
 */
static void hl_touch(const void *buf, __sz len)
{
	__uptr p, end = (__uptr)buf + len;

	if (!len)
		return;
	for (p = (__uptr)buf & ~(__uptr)(__PAGE_SIZE - 1); p < end;
	     p += __PAGE_SIZE)
		(void)*(volatile const __u8 *)MAX(p, (__uptr)buf);
}

static void hl_touch_params(const struct hl_param *params, int nparams)
{
	int i;

	for (i = 0; i < nparams; i++) {
		if (params[i].type == HL_PV_HLSTRING)
			hl_touch(params[i].str.ptr, params[i].str.len);
		else if (params[i].type == HL_PV_HLVECBYTES)
			hl_touch(params[i].vec.ptr, params[i].vec.len);
	}
}

__u64 hl_utf8_decode(const __u8 *s, __u64 len, __u32 *cp)
{
	return hl_pc_utf8_decode(s, len, cp);
}

int hl_utf8_valid(const __u8 *s, __u64 len)
{
	return hl_pc_utf8_valid(s, len);
}

static __u64 hl_query_ulong(const char *name)
{
	__u64 val;

	return hl_hcall_ulong(name, NULL, 0, &val) < 0 ? 0 : val;
}

/* snprintf semantics: report the required length even if it did not fit. */
static int hl_query_string(const char *name, char *out, __sz cap)
{
	__sz len = (__sz)-1;

	if (hl_hcall_string(name, NULL, 0, out, cap, &len) == 0 ||
	    len != (__sz)-1)
		return (int)len;
	return -1;
}

int hl_call_get_cmdline(char *out_buf, __sz buf_sz)
{
	int len = hl_query_string("GetCmdLine", out_buf, buf_sz);

	return len >= 0 && (__sz)len < buf_sz ? len : -1;
}

int hl_call_get_env_vars(char *out_buf, __sz buf_sz)
{
	return hl_query_string("GetEnvVars", out_buf, buf_sz);
}

static __u8 *g_stdin_buf;
static __sz g_stdin_cap;
static __sz g_stdin_pos;
static __sz g_stdin_len;
static int g_stdin_eof;

static int hl_stdin_fetch(void)
{
	__sz len;

	if (!hl_hcall_ready() || g_stdin_eof)
		return 0;
	if (!g_stdin_buf) {
		g_stdin_cap = hl_transport_payload_cap();
		g_stdin_buf = uk_malloc(uk_alloc_get_default(), g_stdin_cap);
		if (unlikely(!g_stdin_buf))
			return 0;
	}
	if (hl_hcall_vecbytes("ReadStdin", NULL, 0, g_stdin_buf, g_stdin_cap,
			      &len) < 0)
		return 0;
	if (len == 0) {
		g_stdin_eof = 1;
		return 0;
	}
	g_stdin_pos = 0;
	g_stdin_len = len;
	return len;
}

int hl_call_read_stdin(char *out_buf, __sz buf_sz)
{
	__sz n;

	if (g_stdin_pos < g_stdin_len) {
		n = MIN(g_stdin_len - g_stdin_pos, buf_sz);
		memcpy(out_buf, g_stdin_buf + g_stdin_pos, n);
		g_stdin_pos += n;
		return (int)n;
	}
	if (hl_stdin_fetch() <= 0)
		return 0;
	n = MIN(g_stdin_len, buf_sz);
	memcpy(out_buf, g_stdin_buf, n);
	g_stdin_pos = n;
	return (int)n;
}

__u64 hl_call_get_paging_budget(void)
{
	return hl_query_ulong("GetPagingBudget");
}

__u64 hl_call_get_initrd_base(void)
{
	return hl_query_ulong("GetInitrdBase");
}

__u64 hl_call_get_initrd_size(void)
{
	return hl_query_ulong("GetInitrdSize");
}

__u64 hl_call_get_exn_stack_top(void)
{
	return hl_query_ulong("GetExnStackTop");
}

__u64 hl_call_get_wall_clock_ns(void)
{
	return hl_query_ulong("GetWallClockNs");
}

struct hl_out {
	void *buf;
	__sz cap;
	__sz len;
};

static int hl_call(const char *func_name, __u8 ret_type,
		   const struct hl_param *params, int nparams,
		   int (*take)(const struct hl_pc_result *, struct hl_out *),
		   struct hl_out *out)
{
	const __u8 *rd;
	__u8 *req;
	__u64 rl, control, reply_control, fc_len;
	struct hl_pc_result result;
	unsigned long irqf;
	int rc = -1, t;

	if (!hl_hcall_ready() || nparams < 0 || nparams > HL_MAX_PARAMS ||
	    (nparams && !params))
		return -1;
	hl_touch_params(params, nparams);
	hl_touch(out->buf, out->cap);
	if (hcall_enter(&irqf) < 0)
		return -1;
	req = hl_transport_request_buf();
	if (!req)
		goto out;
#if CONFIG_HYPERLIGHT_STEP
	if (hyperlight_execution_enabled) {
		struct uk_thread *thread = uk_thread_current();
		__u64 execution = thread ? thread->hyperlight_execution : 0;

		if (execution != g_execution) {
			struct hl_param p = {
				.type = HL_PV_HLULONG, .u64_val = execution
			};
			/* Context and call are one serialized transaction. */
			fc_len = hl_pc_encode_call(req, hl_transport_payload_cap(),
				"ExecutionContext", HL_RT_INT, &p, 1, &control);
			if (!fc_len || hl_transport_call(fc_len, control,
							&rd, &rl, &reply_control) ||
			    hl_pc_decode_result(rd, rl, reply_control, &result) ||
			    result.error || result.tag != 0 || result.value)
				goto out;
			g_execution = execution;
		}
	}
#endif
	fc_len = hl_pc_encode_call(req, hl_transport_payload_cap(),
				  func_name, ret_type, params, nparams, &control);
	t = fc_len ? hl_transport_call(fc_len, control, &rd, &rl,
				       &reply_control) : HL_TRANSPORT_NOT_SENT;
	if (t == 0) {
		if (hl_pc_decode_result(rd, rl, reply_control, &result) < 0)
			rc = HL_HCALL_BAD_RESULT;
		else if (result.error)
			rc = HL_HCALL_REFUSED;
		else
			rc = take(&result, out) < 0 ? HL_HCALL_BAD_RESULT : 0;
	} else if (t == HL_TRANSPORT_BAD_REPLY) {
		rc = HL_HCALL_BAD_RESULT;
	}
out:
	hcall_exit(irqf);
	return rc;
}

int hl_hcall_respond(__u32 cid, const __u8 *payload, __u64 len)
{
	unsigned long irqf;
	int rc;

	if (hcall_enter(&irqf) < 0)
		return -1;
	rc = hl_transport_respond(cid, payload, len);
	hcall_exit(irqf);
	return rc;
}

int hl_hcall_log(__u8 level, const char *source, const char *file,
		 __u32 line, const char *msg, __sz len)
{
	unsigned long irqf;
	__u8 *req;
	__u64 n;
	int rc = -1;

	if (!hl_hcall_ready() || hcall_enter(&irqf) < 0)
		return -1;
	req = hl_transport_request_buf();
	n = req ? hl_pc_encode_log(req, hl_transport_payload_cap(), level,
				  source, file, line, msg, len) : 0;
	if (n && hl_transport_log(n) == 0)
		rc = 0;
	hcall_exit(irqf);
	return rc;
}

static int hl_take_int(const struct hl_pc_result *result, struct hl_out *out)
{
	if (result->tag != 0)
		return -1;
	*(__s32 *)out->buf = (__u32)(result->value >> 1) ^
			    (0U - (__u32)(result->value & 1));
	return 0;
}

static int hl_take_ulong(const struct hl_pc_result *result, struct hl_out *out)
{
	if (result->tag != 3)
		return -1;
	*(__u64 *)out->buf = result->value;
	return 0;
}

static int hl_take_string(const struct hl_pc_result *result, struct hl_out *out)
{
	if (result->tag != 6)
		return -1;
	out->len = result->len;
	if (result->len >= out->cap)
		return -1;
	memcpy(out->buf, result->data, result->len);
	((char *)out->buf)[result->len] = '\0';
	return 0;
}

static int hl_take_vecbytes(const struct hl_pc_result *result, struct hl_out *out)
{
	if (result->tag != 9 || result->len > out->cap)
		return -1;
	if (result->len)
		memcpy(out->buf, result->data, result->len);
	out->len = result->len;
	return 0;
}

int hl_hcall_int(const char *func_name,
		 const struct hl_param *params, int nparams, __s32 *out)
{
	struct hl_out o = { .buf = out, .cap = sizeof(*out) };

	return hl_call(func_name, HL_RT_INT, params, nparams, hl_take_int, &o);
}

int hl_hcall_ulong(const char *func_name,
		   const struct hl_param *params, int nparams, __u64 *out)
{
	struct hl_out o = { .buf = out, .cap = sizeof(*out) };

	return hl_call(func_name, HL_RT_ULONG, params, nparams, hl_take_ulong, &o);
}

int hl_hcall_string(const char *func_name,
		    const struct hl_param *params, int nparams,
		    char *out_buf, __sz buf_sz, __sz *out_len)
{
	struct hl_out o = { .buf = out_buf, .cap = buf_sz, .len = (__sz)-1 };
	int rc = hl_call(func_name, HL_RT_STRING, params, nparams,
			 hl_take_string, &o);

	if (out_len && o.len != (__sz)-1)
		*out_len = o.len;
	return rc;
}

int hl_hcall_vecbytes(const char *func_name,
		      const struct hl_param *params, int nparams,
		      __u8 *out_buf, __sz buf_sz, __sz *out_len)
{
	struct hl_out o = { .buf = out_buf, .cap = buf_sz };
	int rc = hl_call(func_name, HL_RT_VECBYTES, params, nparams,
			 hl_take_vecbytes, &o);

	*out_len = rc == 0 ? o.len : 0;
	return rc;
}

int hl_call_get_random_bytes(__u8 *out_buf, __sz len)
{
	struct hl_param p = { .type = HL_PV_HLULONG, .u64_val = len };
	__sz got;

	if (hl_hcall_vecbytes("GetRandomBytes", &p, 1, out_buf, len, &got) < 0)
		return -1;
	return got == len ? 0 : -1;
}

static __ssz host_write(const char *fn, const char *buf, __sz len)
{
	__u64 max = hl_hcall_max_payload();
	struct hl_param p = { .type = HL_PV_HLVECBYTES };
	__s32 written;
	__sz sent = 0;
	int rc;

	if (!max)
		return -1;
	while (sent < len) {
		__sz n = MIN(len - sent, max), back = 0;

		/* Avoid splitting valid UTF-8 between calls from different threads. */
		if (n < len - sent) {
			while (back < 3 &&
			       (buf[sent + n - back] & 0xc0) == 0x80)
				back++;
			if ((buf[sent + n - back] & 0xc0) != 0x80)
				n -= back;
		}
		p.vec.ptr = (const __u8 *)buf + sent;
		p.vec.len = n;
		rc = hl_hcall_int(fn, &p, 1, &written);
		/* The host ran the call: do not duplicate output on a bad reply. */
		if (rc == HL_HCALL_BAD_RESULT) {
			sent += n;
			continue;
		}
		if (rc < 0)
			return sent ? (__ssz)sent : rc;
		if (written < 0)
			return sent ? (__ssz)sent : -1;
		sent += MIN((__sz)written, n);
		if ((__sz)written < n)
			break;
	}
	return (__ssz)sent;
}

__ssz hl_call_host_write(const char *buf, __sz len)
{
	return host_write("HostWrite", buf, len);
}

__ssz hl_call_host_write_err(const char *buf, __sz len)
{
	return host_write("HostWriteErr", buf, len);
}
