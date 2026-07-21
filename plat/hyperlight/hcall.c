/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2024, Unikraft GmbH and The Unikraft Authors.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

/*
 * /dev/hcall - Hyperlight host function call device
 *
 * Provides a simple interface for user-space to call host functions:
 *   write() - Send JSON request, triggers host call, stores result
 *   read()  - Retrieve JSON result from last call
 *
 * Internally handles FlatBuffer encoding/decoding and shared memory
 * communication with the Hyperlight host via the __dispatch protocol.
 *
 * Protocol:
 *   1. User writes JSON: {"name":"tool_name","args":{...}}
 *   2. Driver encodes as FlatBuffer FunctionCall for __dispatch(VecBytes)
 *   3. Pushes to PEB output_stack, triggers outb(101) VM exit
 *   4. Host decodes, routes to tool handler, encodes result
 *   5. Driver pops result from PEB input_stack
 *   6. Decodes FlatBuffer FunctionCallResult to extract VecBytes
 *   7. User reads JSON result
 */

#include <string.h>
#include <uk/arch/types.h>
#include <uk/print.h>
#include <uk/assert.h>
#include <uk/essentials.h>
#if CONFIG_LIBDEVFS
#include <vfscore/uio.h>
#include <devfs/device.h>
#endif /* CONFIG_LIBDEVFS */

#include <hyperlight-x86/peb.h>
#include <hyperlight-x86/setup.h>
#include <hyperlight-x86/outb.h>
#include <hyperlight-x86/hcall.h>
#include <hyperlight-x86/fb.h>
#ifdef CONFIG_HYPERLIGHT_POLL
#include <hyperlight-x86/poll.h>
#include <uk/lcpu.h>
#endif

/* Maximum payload size for host calls */
#define HCALL_MAX_PAYLOAD 65536

#ifdef CONFIG_HYPERLIGHT_POLL
/* Yield/await protocol (see hyperlight_hcall and plat/hyperlight/poll.c).
 *
 * Every request is wrapped by the guest before sending:
 *   {"__hl_request_id":<u64>,"request":<original request>}
 * <u64> is a guest-allocated monotonically incrementing nonzero ID stored in
 * static guest memory (preserved across snapshots).
 *
 * When the host cannot answer immediately it returns the numeric sentinel:
 *   {"result":{"__hl_yield__":<u64>}}
 * where <u64> echoes the request ID. The guest validates the echoed ID against
 * the allocated one (a mismatch is a protocol error -8), marks the op PENDING,
 * and parks until the next host `poll`. On every poll the host passes a JSON
 * object keyed by decimal ID strings listing completed/errored tasks:
 *   {"42":{"result":<value>}, "7":{"error":"<msg>"}, …}
 *
 * hyperlight_poll_pump() feeds it to hyperlight_hcall_deliver_batch(), which
 * resolves each matching parked op in place and wakes it.
 */
#define HCALL_YIELD_KEY      "\"__hl_yield__\""

/* JSON overhead for the request wrapper:
 *   {"__hl_request_id":<20-digit u64>,"request":} = 52 bytes max.
 * Round up to 64 for headroom.
 */
#define HCALL_WRAP_OVERHEAD  64
#endif /* CONFIG_HYPERLIGHT_POLL */

/* ========================================================================
 * FlatBuffer Encoder
 * ========================================================================
 *
 * Encodes exactly one FlatBuffer shape:
 *   FunctionCall {
 *     function_name: "__dispatch",
 *     parameters: [Parameter { value: hlvecbytes { value: <payload> } }],
 *     function_call_type: Host(2),
 *     expected_return_type: hlsizeprefixedbuffer(9)
 *   }
 *
 * The FlatBuffer is size-prefixed. The fixed template (bytes 4-95) is
 * constant for all payloads. Only the size prefix (bytes 0-3) and
 * payload vector (bytes 96+) vary.
 *
 * Total size: 100 + ALIGN4(payload_len)
 */

/*
 * Fixed template: bytes 4-95 of the encoded FlatBuffer (92 bytes).
 * Contains: root_offset, FunctionCall vtable+table, "__dispatch" string,
 * parameters vector, Parameter vtable+table, hlvecbytes vtable+table.
 * All internal offsets are pre-computed and constant.
 */
static const __u8 hcall_fb_template[92] = {
	/* root_offset = 16 (from byte 4 to FunctionCall table at byte 20) */
	0x10, 0x00, 0x00, 0x00,

	/* FunctionCall vtable (12 bytes at offset 8) */
	0x0C, 0x00,             /* vtable_size = 12 */
	0x10, 0x00,             /* table_inline_size = 16 */
	0x04, 0x00,             /* VT[4] function_name at table+4 */
	0x08, 0x00,             /* VT[6] parameters at table+8 */
	0x0C, 0x00,             /* VT[8] function_call_type at table+12 */
	0x0D, 0x00,             /* VT[10] expected_return_type at table+13 */

	/* FunctionCall table (16 bytes at offset 20) */
	0x0C, 0x00, 0x00, 0x00, /* soffset to vtable = 20-8 = 12 */
	0x0C, 0x00, 0x00, 0x00, /* fn_name offset = 36-24 = 12 */
	0x18, 0x00, 0x00, 0x00, /* params offset = 52-28 = 24 */
	0x02,                   /* function_call_type = Host(2) */
	0x09,                   /* expected_return_type = hlsizeprefixedbuffer(9) */
	0x00, 0x00,             /* padding */

	/* function_name string "__dispatch" (16 bytes at offset 36) */
	0x0A, 0x00, 0x00, 0x00, /* length = 10 */
	0x5F, 0x5F, 0x64, 0x69, /* "__di" */
	0x73, 0x70, 0x61, 0x74, /* "spat" */
	0x63, 0x68,             /* "ch" */
	0x00,                   /* NUL terminator */
	0x00,                   /* padding to 4-byte alignment */

	/* parameters vector (8 bytes at offset 52) */
	0x01, 0x00, 0x00, 0x00, /* length = 1 */
	0x0C, 0x00, 0x00, 0x00, /* offset to Parameter table = 68-56 = 12 */

	/* Parameter vtable (8 bytes at offset 60) */
	0x08, 0x00,             /* vtable_size = 8 */
	0x0C, 0x00,             /* table_inline_size = 12 */
	0x04, 0x00,             /* VT[4] value_type at table+4 */
	0x08, 0x00,             /* VT[6] value at table+8 */

	/* Parameter table (12 bytes at offset 68) */
	0x08, 0x00, 0x00, 0x00, /* soffset to vtable = 68-60 = 8 */
	0x09, 0x00, 0x00, 0x00, /* value_type=hlvecbytes(9) + 3 bytes padding */
	0x0C, 0x00, 0x00, 0x00, /* value offset = 88-76 = 12 */

	/* hlvecbytes vtable (6 bytes + 2 padding at offset 80) */
	0x06, 0x00,             /* vtable_size = 6 */
	0x08, 0x00,             /* table_inline_size = 8 */
	0x04, 0x00,             /* VT[4] value at table+4 */
	0x00, 0x00,             /* padding to 4-byte alignment */

	/* hlvecbytes table (8 bytes at offset 88) */
	0x08, 0x00, 0x00, 0x00, /* soffset to vtable = 88-80 = 8 */
	0x04, 0x00, 0x00, 0x00, /* value offset = 96-92 = 4 */
};

#define FB_TEMPLATE_OFFSET 4  /* template starts at byte 4 in output */
#define FB_HEADER_SIZE     100 /* fixed overhead before payload data */

/**
 * Encode a __dispatch host function call as a size-prefixed FlatBuffer.
 *
 * @param buf Output buffer (must be >= FB_HEADER_SIZE + ALIGN4(payload_len))
 * @param buf_sz Size of output buffer
 * @param payload JSON payload bytes
 * @param payload_len Length of payload
 * @return Total encoded size, or 0 on error
 */
static __sz hcall_encode(__u8 *buf, __sz buf_sz,
			 const __u8 *payload, __sz payload_len)
{
	__sz aligned_len = (payload_len + 3) & ~(__sz)3;
	__sz total_size = FB_HEADER_SIZE + aligned_len;

	if (total_size > buf_sz)
		return 0;

	/* Byte 0-3: size prefix (total - 4) */
	__u32 sp = (__u32)(total_size - 4);

	buf[0] = sp & 0xFF;
	buf[1] = (sp >> 8) & 0xFF;
	buf[2] = (sp >> 16) & 0xFF;
	buf[3] = (sp >> 24) & 0xFF;

	/* Bytes 4-95: fixed template */
	memcpy(buf + FB_TEMPLATE_OFFSET, hcall_fb_template,
	       sizeof(hcall_fb_template));

	/* Byte 96-99: payload vector length */
	__u32 plen = (__u32)payload_len;

	buf[96] = plen & 0xFF;
	buf[97] = (plen >> 8) & 0xFF;
	buf[98] = (plen >> 16) & 0xFF;
	buf[99] = (plen >> 24) & 0xFF;

	/* Byte 100+: payload data + padding */
	if (payload_len > 0)
		memcpy(buf + FB_HEADER_SIZE, payload, payload_len);
	if (aligned_len > payload_len)
		memset(buf + FB_HEADER_SIZE + payload_len, 0,
		       aligned_len - payload_len);

	return total_size;
}

/* ========================================================================
 * FlatBuffer Decoder
 * ========================================================================
 * Decodes FunctionCallResult to extract the VecBytes return payload.
 *
 * Expected structure:
 *   FunctionCallResult {
 *     result_type: ReturnValueBox(1),
 *     result: ReturnValueBox {
 *       value_type: hlsizeprefixedbuffer(10),
 *       value: hlsizeprefixedbuffer { size: i32, value: [ubyte] }
 *     }
 *   }
 */

/* FlatBuffer reader helpers (hl_fb_*) live in include/hyperlight-x86/fb.h
 * so plat code outside this file (e.g. dispatch.c) can share them.
 */

/* Union discriminant values for decoding */
#define FCR_RESULT_TYPE_RVBOX     1   /* FunctionCallResultType::ReturnValueBox */
#define RV_TYPE_SIZEPREFIXEDBUF  10   /* ReturnValue::hlsizeprefixedbuffer */

/**
 * Decode a FunctionCallResult FlatBuffer to extract the VecBytes payload.
 *
 * @param buf Size-prefixed FlatBuffer data
 * @param buf_len Length of buffer
 * @param out_data Output: pointer to result bytes (within buf)
 * @param out_len Output: length of result bytes
 * @return 0 on success, negative on error
 */
static int hcall_decode(const __u8 *buf, __sz buf_len,
			const __u8 **out_data, __sz *out_len)
{
	if (buf_len < 8)
		return -1;

	/* Root table (size-prefixed: skip 4-byte prefix) */
	__u32 root_off = hl_fb_u32(buf, 4);
	__sz fcr = 4 + root_off;

	/* FunctionCallResult.result_type (VT=4) == ReturnValueBox(1)? */
	__u8 result_type = hl_fb_u8f(buf, fcr, 4, 0);

	if (result_type != FCR_RESULT_TYPE_RVBOX)
		return -2;

	/* Follow result (VT=6) -> ReturnValueBox */
	__sz rvb = hl_fb_follow(buf, fcr, 6);

	if (rvb == 0)
		return -3;

	/* ReturnValueBox.value_type (VT=4) == hlsizeprefixedbuffer(10)? */
	__u8 value_type = hl_fb_u8f(buf, rvb, 4, 0);

	if (value_type != RV_TYPE_SIZEPREFIXEDBUF)
		return -4;

	/* Follow value (VT=6) -> hlsizeprefixedbuffer */
	__sz spb = hl_fb_follow(buf, rvb, 6);

	if (spb == 0)
		return -5;

	/* Follow value vector (VT=6) -> byte vector */
	__sz vec = hl_fb_follow(buf, spb, 6);

	if (vec == 0)
		return -6;

	__u32 vec_len = hl_fb_u32(buf, vec);

	*out_data = buf + vec + 4;
	*out_len = vec_len;

	return 0;
}

/* ========================================================================
 * Shared Memory Stack Protocol
 * ========================================================================
 * Implements push (to output_stack) and pop (from input_stack)
 * matching Hyperlight's io.rs protocol.
 *
 * Stack layout:
 *   [stack_ptr:u64] [data] [back_ptr:u64] [data] [back_ptr:u64] ...
 *
 * stack_ptr at offset 0 points to next free byte (initially 8).
 * Each push appends: data bytes + back_ptr (8 bytes = old stack_ptr).
 * Each pop reads back_ptr to find data start, resets stack_ptr.
 */

static inline __u64 read_u64_le(const __u8 *p)
{
	return p[0] | ((__u64)p[1] << 8) | ((__u64)p[2] << 16) |
	       ((__u64)p[3] << 24) | ((__u64)p[4] << 32) |
	       ((__u64)p[5] << 40) | ((__u64)p[6] << 48) |
	       ((__u64)p[7] << 56);
}

static inline void write_u64_le(__u8 *p, __u64 v)
{
	p[0] = v & 0xFF;
	p[1] = (v >> 8) & 0xFF;
	p[2] = (v >> 16) & 0xFF;
	p[3] = (v >> 24) & 0xFF;
	p[4] = (v >> 32) & 0xFF;
	p[5] = (v >> 40) & 0xFF;
	p[6] = (v >> 48) & 0xFF;
	p[7] = (v >> 56) & 0xFF;
}

/**
 * Push data onto a shared memory stack (output_stack).
 */
static int hcall_push(__u8 *stack, __u64 stack_size,
		      const __u8 *data, __sz data_len)
{
	__u64 sp = read_u64_le(stack);

	if (sp < 8 || sp > stack_size)
		return -1;

	/* Need space for data + 8-byte back pointer */
	if (sp + data_len + 8 > stack_size)
		return -1;

	/* Write data */
	memcpy(stack + sp, data, data_len);

	/* Write back pointer (old sp) after data */
	write_u64_le(stack + sp + data_len, sp);

	/* Update stack pointer */
	write_u64_le(stack, sp + data_len + 8);

	return 0;
}

/**
 * Pop data from a shared memory stack (input_stack).
 * Returns pointer into the stack buffer (valid until next pop/push).
 */
static int hcall_pop(__u8 *stack, __u64 stack_size,
		     const __u8 **out_data, __sz *out_len)
{
	__u64 sp = read_u64_le(stack);

	if (sp < 16 || sp > stack_size)
		return -1;

	/* Read back pointer (8 bytes before current sp) */
	__u64 back_ptr = read_u64_le(stack + sp - 8);

	if (back_ptr < 8 || back_ptr >= sp)
		return -1;

	*out_data = stack + back_ptr;
	*out_len = sp - 8 - back_ptr;

	/* Reset stack pointer to free the popped data.
	 * Note: we do NOT zero the freed region here because out_data
	 * points into it and the caller still needs to read the data.
	 */
	write_u64_le(stack, back_ptr);

	return 0;
}

/* ========================================================================
 * Public API: hyperlight_hcall()
 * ========================================================================
 *
 * One shared FlatBuffer encode buffer (static; request payloads are
 * bounded by HCALL_MAX_PAYLOAD). Callers provide their own request and
 * response buffers so the API is stateless across calls — a single
 * thread running one dispatch at a time is the expected use.
 */
static __u8 hcall_encode_buf[HCALL_MAX_PAYLOAD + 256];

static int hyperlight_hcall_once(const __u8 *req, __sz req_len,
				 __u8 *resp, __sz resp_cap, __sz *resp_len)
{
	struct hyperlight_peb *peb = hyperlight_get_peb();
	__u8 *output_stack;
	__u64 output_size;
	__u8 *input_stack;
	__u64 input_size;
	__sz fb_len;
	const __u8 *result_fb;
	__sz result_fb_len;
	const __u8 *payload_data;
	__sz payload_len;
	int rc;

	if (!peb)
		return -1;

	output_stack = (__u8 *)peb->output_stack.ptr;
	output_size = peb->output_stack.size;
	input_stack = (__u8 *)peb->input_stack.ptr;
	input_size = peb->input_stack.size;

	if (!output_stack || !input_stack ||
	    output_size == 0 || input_size == 0)
		return -2;

	/* 1. Encode FlatBuffer */
	fb_len = hcall_encode(hcall_encode_buf, sizeof(hcall_encode_buf),
			      req, req_len);
	if (fb_len == 0)
		return -3;

	/* 2. Push to output_stack */
	rc = hcall_push(output_stack, output_size,
			hcall_encode_buf, fb_len);
	if (rc < 0)
		return -4;

	/* 3. Trigger host function call (VM exit) */
	hyperlight_out32(HYPERLIGHT_OUTB_CALL_FUNCTION, 0);

	/* 4. Pop result from input_stack */
	rc = hcall_pop(input_stack, input_size,
		       &result_fb, &result_fb_len);
	if (rc < 0)
		return -5;

	/* 5. Decode FlatBuffer result */
	rc = hcall_decode(result_fb, result_fb_len,
			  &payload_data, &payload_len);
	if (rc < 0)
		return -6;

	/* 6. Copy into caller's buffer */
	if (payload_len > resp_cap)
		return -7;
	memcpy(resp, payload_data, payload_len);
	if (resp_len)
		*resp_len = payload_len;

	return 0;
}

#ifdef CONFIG_HYPERLIGHT_POLL
/* Bounded forward search for `needle` (length nlen) within `hay` (length
 * hlen). Returns a pointer to the first match or NULL. hay is not assumed to
 * be NUL-terminated, so we cannot use strstr().
 */
static const __u8 *hcall_memmem(const __u8 *hay, __sz hlen,
				const char *needle, __sz nlen)
{
	if (nlen == 0 || hlen < nlen)
		return __NULL;

	for (__sz i = 0; i + nlen <= hlen; i++) {
		if (memcmp(hay + i, needle, nlen) == 0)
			return hay + i;
	}
	return __NULL;
}

/* ------------------------------------------------------------------ *
 * Pending-op registry.
 *
 * Parked host calls register their struct hyperlight_hcall_op here
 * keyed by the op's guest-allocated request_id (nonzero u64). On each
 * host `poll`, hyperlight_poll_pump() calls hyperlight_hcall_deliver_batch()
 * with the JSON object of all completed/errored tasks; each matching op
 * is resolved in place and unregistered. The list is mutated only from
 * the (single, cooperatively-scheduled) vCPU, but a thread can be woken
 * from the wait queue between list operations, so mutations are guarded
 * by a brief IRQ-off critical section.
 * ------------------------------------------------------------------ */
static struct hyperlight_hcall_op *hl_pending_ops;

/* Monotonically increasing, nonzero request-ID counter, stored in static
 * guest memory (preserved across snapshots). Skips 0 on wrap.
 */
static __u64 hl_next_request_id = 1;

/* Wrapping buffer for {"__hl_request_id":<id>,"request":<req>}.
 *
 * Shared static, like hcall_encode_buf: it is filled and consumed within a
 * single hyperlight_hcall_submit() call with no intervening cooperative yield
 * (hyperlight_hcall_once() only encodes, pushes and triggers the VM exit — it
 * never parks), so the "one dispatch at a time" invariant that guards
 * hcall_encode_buf covers this buffer too. Back-to-back multi-await submits run
 * sequentially on the vCPU and cannot interleave mid-wrap.
 */
static __u8 hl_wrap_buf[HCALL_MAX_PAYLOAD + HCALL_WRAP_OVERHEAD];

/* Stable snapshot of the most recent poll batch. deliver_batch() copies the
 * host's poll argument here (NOT into each caller's response buffer) so the
 * result survives until the parked caller is scheduled and reads it. This
 * matters because a caller's response buffer is typically a shared static
 * (e.g. hostsock's rpc_resp): between the poll pump copying a result and the
 * woken caller reading it, other cooperatively-scheduled threads may run and
 * clobber that shared buffer. hl_batch_buf is written only by the pump (IRQs
 * off, no concurrent writer) and read by each woken caller's poll() before it
 * consults its response buffer, so it is stable across the wake window. It is
 * only overwritten on the next pump, by which point every caller woken by the
 * previous pump has already run (the pump returns to the host only once the
 * scheduler is idle) and copied out its value.
 */
static __u8 hl_batch_buf[HCALL_MAX_PAYLOAD];
static __sz hl_batch_len;

static void hcall_registry_add(struct hyperlight_hcall_op *op)
{
	unsigned long flags = uk_lcpu_save_irqf();

	op->next = hl_pending_ops;
	hl_pending_ops = op;

	uk_lcpu_restore_irqf(flags);
}

/* Remove @op from the registry if present. Idempotent: a no-op when @op
 * was already delivered/removed (so callers can unregister defensively).
 */
static void hcall_registry_del(struct hyperlight_hcall_op *op)
{
	struct hyperlight_hcall_op **pp;
	unsigned long flags = uk_lcpu_save_irqf();

	for (pp = &hl_pending_ops; *pp; pp = &(*pp)->next) {
		if (*pp == op) {
			*pp = op->next;
			op->next = __NULL;
			break;
		}
	}

	uk_lcpu_restore_irqf(flags);
}

/* Convert a nonzero u64 to its decimal ASCII representation (no NUL).
 * Returns the number of digits written into buf, or 0 if buf is too small.
 * buf must be at least 20 bytes for the worst-case 20-digit u64.
 */
static __sz u64_to_decimal(__u64 v, char *buf, __sz buf_sz)
{
	char tmp[20];
	__sz n = 0;

	if (v == 0) {
		if (buf_sz < 1)
			return 0;
		buf[0] = '0';
		return 1;
	}
	while (v > 0 && n < sizeof(tmp)) {
		tmp[n++] = (char)('0' + (int)(v % 10));
		v /= 10;
	}
	if (n > buf_sz)
		return 0;
	for (__sz i = 0; i < n; i++)
		buf[i] = tmp[n - 1 - i];
	return n;
}

/* Return 1 if @id is already registered in the pending-op list, 0 otherwise.
 * Callers must hold the registry IRQ-off critical section (see hcall_alloc_id)
 * so the walk sees a stable list.
 */
static int hcall_id_in_use(__u64 id)
{
	struct hyperlight_hcall_op *op;

	for (op = hl_pending_ops; op; op = op->next)
		if (op->request_id == id)
			return 1;
	return 0;
}

/* Allocate the next available nonzero monotone request ID.
 *
 * Advances hl_next_request_id, skipping 0 on wrap, and retries up to 64
 * times if the candidate ID is already live in the pending-op registry (can
 * only happen after a full 2^64 wrap cycle). Returns 0 when all 64 candidates
 * are in use, which is treated as exhaustion (-9) by the caller.
 *
 * The counter bump and registry scan run in a single IRQ-off critical section,
 * matching hcall_registry_add()/del(). The cooperative single-vCPU scheduler
 * cannot switch callers between allocation and registration because that path
 * contains no scheduler yield.
 */
static __u64 hcall_alloc_id(void)
{
	unsigned long flags = uk_lcpu_save_irqf();
	__u64 result = 0;
	int tries;

	for (tries = 0; tries < 64; tries++) {
		__u64 id = hl_next_request_id++;

		if (hl_next_request_id == 0)
			hl_next_request_id = 1; /* skip 0 on wrap */
		if (!hcall_id_in_use(id)) {
			result = id;
			break;
		}
	}

	uk_lcpu_restore_irqf(flags);
	return result; /* 0 == exhausted */
}

/* Build the wrapped request in hl_wrap_buf:
 *   {"__hl_request_id":<id>,"request":<req>}
 * Returns the total byte count, or 0 if the result does not fit.
 */
static __sz hcall_wrap_request(__u64 id, const __u8 *req, __sz req_len)
{
	static const char pfx[] = "{\"__hl_request_id\":";
	static const char mid[] = ",\"request\":";
	char id_str[20];
	__sz id_len = u64_to_decimal(id, id_str, sizeof(id_str));
	__sz total;

	if (id_len == 0)
		return 0;
	/* pfx + id + mid + req + '}' */
	total = (sizeof(pfx) - 1) + id_len + (sizeof(mid) - 1) + req_len + 1;
	if (total > sizeof(hl_wrap_buf))
		return 0;

	__sz pos = 0;

	memcpy(hl_wrap_buf + pos, pfx, sizeof(pfx) - 1);
	pos += sizeof(pfx) - 1;
	memcpy(hl_wrap_buf + pos, id_str, id_len);
	pos += id_len;
	memcpy(hl_wrap_buf + pos, mid, sizeof(mid) - 1);
	pos += sizeof(mid) - 1;
	if (req_len > 0)
		memcpy(hl_wrap_buf + pos, req, req_len);
	pos += req_len;
	hl_wrap_buf[pos++] = '}';
	return pos;
}

/* Classify `resp` as a numeric yield sentinel and extract the ID.
 *
 * Returns:
 *    1  yield sentinel; *out_id set to the nonzero u64 numeric value.
 *    0  not a yield sentinel (no "__hl_yield__" key present).
 *   -1  "__hl_yield__" key present but value is not a valid nonzero u64
 *       (wrong type, malformed, zero, or overflow) — protocol error.
 *
 * Recognises {"result":{"__hl_yield__":<u64>}} and any payload containing
 * the key. The value must be a bare integer (no quotes).
 */
static int hcall_extract_yield_id(const __u8 *resp, __sz len, __u64 *out_id)
{
	const __u8 *p = hcall_memmem(resp, len, HCALL_YIELD_KEY,
				     sizeof(HCALL_YIELD_KEY) - 1);
	const __u8 *end = resp + len;
	__u64 v;

	if (!p)
		return 0;

	/* Advance past the key, then whitespace and ':'. */
	p += sizeof(HCALL_YIELD_KEY) - 1;
	while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))
		p++;
	if (p >= end || *p != ':')
		return -1;
	p++;
	while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))
		p++;

	/* Value must be a decimal integer (bare, no quotes). */
	if (p >= end || *p < '0' || *p > '9')
		return -1;

	v = 0;
	while (p < end && *p >= '0' && *p <= '9') {
		__u64 d = (__u64)(*p++ - '0');
		/* Overflow check */
		if (v > ((__u64)-1 / 10) ||
		    (v == ((__u64)-1 / 10) && d > ((__u64)-1 % 10)))
			return -1;
		v = v * 10 + d;
	}
	/* The number must be terminated by a JSON delimiter (whitespace, ',',
	 * '}', or end of buffer). Reject trailing junk such as "42x" or a
	 * fractional/exponent form ("4.2", "4e2") that would otherwise be
	 * silently truncated to a bogus ID.
	 */
	if (p < end && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r' &&
	    *p != ',' && *p != '}')
		return -1;
	if (v == 0)
		return -1; /* ID must be nonzero */
	*out_id = v;
	return 1;
}

/* Locate the value object for the decimal key "<id_str>" in the batch object
 * {"<decimal-id>":{…}, …}. On success sets *out/*out_len to the balanced {…}
 * value (verbatim, ready to hand back as the op's response) and returns 1;
 * returns 0 if the key is absent or the value is malformed.
 *
 * Keys are decimal string representations of u64 request IDs; the surrounding
 * quotes make the match immune to one ID string being a prefix of another. The
 * value scan honours JSON strings and escapes so braces inside string values
 * don't throw off the brace-depth counter.
 */
static int hcall_batch_find(const __u8 *json, __sz json_len,
			    const __u8 *tok, __sz tok_len,
			    const __u8 **out, __sz *out_len)
{
	const __u8 *end = json + json_len;
	const __u8 *p = json;

	while (p < end) {
		const __u8 *q;
		const __u8 *v;
		int depth;
		int instr;

		if (*p != '"') {
			p++;
			continue;
		}
		/* Need `"` + tok + `"` to fit before end. */
		if ((__sz)(end - (p + 1)) < tok_len + 1) {
			p++;
			continue;
		}
		if (memcmp(p + 1, tok, tok_len) != 0 ||
		    p[1 + tok_len] != '"') {
			p++;
			continue;
		}

		/* Matched key "<tok>"; expect ws ':' ws '{'. */
		q = p + 1 + tok_len + 1;
		while (q < end && (*q == ' ' || *q == '\t' ||
				   *q == '\n' || *q == '\r'))
			q++;
		if (q >= end || *q != ':') {
			p++;
			continue;
		}
		q++;
		while (q < end && (*q == ' ' || *q == '\t' ||
				   *q == '\n' || *q == '\r'))
			q++;
		if (q >= end || *q != '{')
			return 0;

		/* Scan a balanced object, honouring strings/escapes. */
		v = q;
		depth = 0;
		instr = 0;
		while (q < end) {
			__u8 c = *q;

			if (instr) {
				if (c == '\\') {
					q += 2;
					continue;
				}
				if (c == '"')
					instr = 0;
				q++;
				continue;
			}
			if (c == '"') {
				instr = 1;
				q++;
				continue;
			}
			if (c == '{') {
				depth++;
			} else if (c == '}') {
				depth--;
				if (depth == 0) {
					q++;
					*out = v;
					*out_len = (__sz)(q - v);
					return 1;
				}
			}
			q++;
		}
		return 0; /* unterminated value */
	}
	return 0;
}

void hyperlight_hcall_deliver_batch(const __u8 *json, __sz json_len)
{
	struct hyperlight_hcall_op *op;
	struct hyperlight_hcall_op *next;

	if (!json || json_len == 0)
		return;

	/* Snapshot the batch into the stable kernel buffer. Each woken caller
	 * re-scans this (in hyperlight_hcall_poll) for its own request_id and
	 * copies the value into its response buffer on its own thread, right
	 * before it reads that buffer — avoiding the shared-response-buffer
	 * clobber window (see hl_batch_buf).
	 */
	if (json_len > sizeof(hl_batch_buf))
		json_len = sizeof(hl_batch_buf);
	memcpy(hl_batch_buf, json, json_len);
	hl_batch_len = json_len;

	/* Mark every registered PENDING op whose decimal ID key is in the
	 * batch READY and unregister it; the value copy is deferred to poll().
	 * The list is only grown by not-yet-parked threads and we run with the
	 * woken threads still blocked, so walking it here is safe.
	 */
	for (op = hl_pending_ops; op; op = next) {
		char id_str[20];
		__sz id_len;
		const __u8 *val;
		__sz val_len;

		next = op->next;

		if (op->state != HYPERLIGHT_HCALL_PENDING || !op->request_id)
			continue;
		id_len = u64_to_decimal(op->request_id, id_str, sizeof(id_str));
		if (!id_len)
			continue;
		if (!hcall_batch_find(hl_batch_buf, hl_batch_len,
				      (const __u8 *)id_str, id_len,
				      &val, &val_len))
			continue;
		op->state = HYPERLIGHT_HCALL_READY;
		hcall_registry_del(op);
	}
}

int hyperlight_hcall_submit(struct hyperlight_hcall_op *op,
			    const __u8 *req, __sz req_len,
			    __u8 *resp, __sz resp_cap)
{
	__u64 id;
	__sz wrap_len;
	__sz got = 0;
	__u64 yield_id;
	int rc, y;

	UK_ASSERT(op);

	op->resp = resp;
	op->resp_cap = resp_cap;
	op->resp_len = 0;
	op->request_id = 0;
	op->next = __NULL;
	op->state = HYPERLIGHT_HCALL_READY;

	/* Allocate a nonzero request ID, collision-free with active ops. */
	id = hcall_alloc_id();
	if (!id)
		return -9; /* ID space exhausted */

	/* Wrap: {"__hl_request_id":<id>,"request":<req>} */
	wrap_len = hcall_wrap_request(id, req, req_len);
	if (!wrap_len)
		return -3; /* request too large to wrap */

	rc = hyperlight_hcall_once(hl_wrap_buf, wrap_len, resp, resp_cap, &got);
	if (rc < 0)
		return rc;
	op->resp_len = got;

	/* Classify the response: no __hl_yield__ key → READY with real result;
	 * valid numeric yield ID matching @id → PENDING, register for delivery;
	 * any other case (malformed, mismatched ID) → protocol error -8.
	 */
	y = hcall_extract_yield_id(resp, got, &yield_id);
	if (y == 0)
		return 0; /* real result, op stays READY */
	if (y < 0 || yield_id != id)
		return -8; /* malformed or mismatched yield ID */

	op->request_id = id;
	op->state = HYPERLIGHT_HCALL_PENDING;
	hcall_registry_add(op);
	return 0;
}

int hyperlight_hcall_poll(struct hyperlight_hcall_op *op)
{
	UK_ASSERT(op);

	/* Completion is signalled out-of-band by hyperlight_hcall_deliver_batch
	 * (from the poll pump), which marks the op READY. The value itself is
	 * copied here, on the caller's own thread, so that the window between
	 * this copy and the caller consuming op->resp contains no cooperative
	 * yield — a shared response buffer cannot be clobbered by another
	 * thread in between (see hl_batch_buf).
	 */
	if (op->state == HYPERLIGHT_HCALL_READY) {
		if (op->request_id) {
			char id_str[20];
			__sz id_len = u64_to_decimal(op->request_id, id_str,
						     sizeof(id_str));
			const __u8 *val;
			__sz val_len;

			if (id_len &&
			    hcall_batch_find(hl_batch_buf, hl_batch_len,
					     (const __u8 *)id_str, id_len,
					     &val, &val_len)) {
				if (val_len > op->resp_cap)
					val_len = op->resp_cap;
				memcpy(op->resp, val, val_len);
				op->resp_len = val_len;
			}
		}
		return 1;
	}
	if (!op->request_id)
		return -8; /* pending but no valid request ID */
	return 0;	   /* still pending */
}
#endif /* CONFIG_HYPERLIGHT_POLL */

int hyperlight_hcall(const __u8 *req, __sz req_len,
		     __u8 *resp, __sz resp_cap, __sz *resp_len)
{
#ifdef CONFIG_HYPERLIGHT_POLL
	struct hyperlight_hcall_op op;
	int rc = hyperlight_hcall_submit(&op, req, req_len, resp, resp_cap);

	if (rc < 0)
		return rc;

	/* Await loop. While the host reports the operation is still pending —
	 * a numeric yield sentinel — park until the next host `poll`. Each poll
	 * pump delivers all completed/errored task results via
	 * hyperlight_hcall_deliver_batch(), which resolves this op in place if
	 * its decimal request_id key is among them; the state check below then
	 * sees READY. The caller's stack is preserved across the VM exit, so on
	 * resume execution continues exactly where it left off. Outside a poll
	 * pump (or on the pump host thread) we cannot park, so the yield
	 * sentinel is returned to the caller as-is.
	 *
	 * This is the single-await specialisation of the submit/poll primitives
	 * above; multi-await callers submit several ops and poll each across
	 * successive host `poll`s instead.
	 */
	while (op.state == HYPERLIGHT_HCALL_PENDING &&
	       hyperlight_poll_current_can_park()) {
		hyperlight_hcall_park_retry();

		rc = hyperlight_hcall_poll(&op);
		if (rc < 0) {
			hcall_registry_del(&op);
			return rc;
		}
	}

	/* Defensively unregister: covers the unparkable path (op still PENDING
	 * but we're returning the raw sentinel) so the registry never retains a
	 * pointer to this about-to-be-freed on-stack op. Idempotent when the op
	 * was already delivered/removed.
	 */
	hcall_registry_del(&op);

	if (resp_len)
		*resp_len = op.resp_len;
	return 0;
#else /* !CONFIG_HYPERLIGHT_POLL */
	__sz got = 0;
	int rc = hyperlight_hcall_once(req, req_len, resp, resp_cap, &got);

	if (resp_len)
		*resp_len = got;
	return rc;
#endif /* CONFIG_HYPERLIGHT_POLL */
}

/* ========================================================================
 * /dev/hcall Device Driver
 *
 * Only built when devfs is available. The in-kernel hyperlight_hcall()
 * primitive above is always compiled so kernel components (poll, hostfs,
 * hostsock, time) can call the host without a devfs round-trip.
 * ======================================================================== */

#if CONFIG_LIBDEVFS

/* Static buffers — user-space device tracks the last response across
 * read() calls (see dev_hcall_read for the pos/len state machine).
 */
static __u8 hcall_req_buf[HCALL_MAX_PAYLOAD];
static __sz hcall_req_len;

static __u8 hcall_result_buf[HCALL_MAX_PAYLOAD];
static __sz hcall_result_len;
static __sz hcall_result_pos;

/**
 * Execute the __dispatch host function call (/dev/hcall internal wrapper).
 */
static int hcall_dispatch(void)
{
	int rc;

	rc = hyperlight_hcall(hcall_req_buf, hcall_req_len,
			      hcall_result_buf, sizeof(hcall_result_buf),
			      &hcall_result_len);
	hcall_result_pos = 0;
	return rc;
}

/**
 * Write handler: receive JSON request and dispatch to host.
 */
static int dev_hcall_write(struct device *dev __unused,
			   struct uio *uio, int flags __unused)
{
	__sz len = uio->uio_iov->iov_len;
	int rc;

	if (len > HCALL_MAX_PAYLOAD)
		return ENOMEM;

	/* Copy request data */
	memcpy(hcall_req_buf, uio->uio_iov->iov_base, len);
	hcall_req_len = len;

	/* Dispatch to host */
	rc = hcall_dispatch();
	if (rc < 0) {
		/* Encode error step into JSON so user-space can diagnose:
		 * -1: null PEB
		 * -2: null/zero stacks
		 * -3: FlatBuffer encode failed
		 * -4: push to output_stack failed
		 * -5: pop from input_stack failed
		 * -6: FlatBuffer decode failed
		 */
		char err[64];
		int n = 0;
		int abs_rc = rc < 0 ? -rc : rc;

		/* sprintf not available, format manually */
		memcpy(err, "{\"error\":\"hcall step ", 21);
		n = 21;
		if (abs_rc >= 10)
			err[n++] = '0' + (abs_rc / 10);
		err[n++] = '0' + (abs_rc % 10);
		memcpy(err + n, " failed\"}", 9);
		n += 9;

		memcpy(hcall_result_buf, err, n);
		hcall_result_len = n;
		hcall_result_pos = 0;
	}

	uio->uio_resid = 0;
	return 0;
}

/**
 * Read handler: return result from last dispatch call.
 */
static int dev_hcall_read(struct device *dev __unused,
			  struct uio *uio, int flags __unused)
{
	__sz avail = hcall_result_len - hcall_result_pos;
	__sz len = uio->uio_iov->iov_len;

	if (avail == 0) {
		/* No more data - signal EOF */
		return 0;
	}

	if (len > avail)
		len = avail;

	memcpy(uio->uio_iov->iov_base,
	       hcall_result_buf + hcall_result_pos, len);
	hcall_result_pos += len;
	uio->uio_resid = uio->uio_iov->iov_len - len;

	return 0;
}

static struct devops hcall_devops = {
	.open  = dev_noop_open,
	.close = dev_noop_close,
	.read  = dev_hcall_read,
	.write = dev_hcall_write,
	.ioctl = dev_noop_ioctl,
};

static struct driver drv_hcall = {
	.devops = &hcall_devops,
	.devsz  = 0,
	.name   = "hcall",
};

static int devfs_register_hcall(struct uk_init_ctx *ictx __unused)
{
	int rc;

	rc = device_create(&drv_hcall, "hcall", D_CHR, NULL);
	if (unlikely(rc)) {
		uk_pr_err("Failed to register /dev/hcall: %d\n", rc);
		return -rc;
	}

	uk_pr_info("Registered /dev/hcall\n");
	return 0;
}

devfs_initcall(devfs_register_hcall);

#endif /* CONFIG_LIBDEVFS */
