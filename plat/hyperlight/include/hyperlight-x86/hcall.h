/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2025, Unikraft GmbH and The Unikraft Authors.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

/*
 * In-kernel API for issuing Hyperlight __dispatch host function calls.
 *
 * The /dev/hcall user-space device exposes this via read/write; other
 * kernel components (e.g. lib/hostfs) can call it directly to avoid the
 * round-trip through devfs.
 */

#ifndef __HYPERLIGHT_HCALL_H__
#define __HYPERLIGHT_HCALL_H__

#include <uk/arch/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Issue a synchronous __dispatch host function call.
 *
 * The request payload is opaque to this API; convention is a JSON object
 * of the form {"name":"<tool>","args":{…}} that the host recognises.
 *
 * Under CONFIG_HYPERLIGHT_POLL the request is wrapped as
 * {"__hl_request_id":<u64>,"request":<original>} before sending; the u64 is
 * a guest-allocated monotonically incrementing nonzero ID (static guest
 * memory, preserved across snapshots). The host echoes the ID as a numeric
 * yield sentinel {"result":{"__hl_yield__":<u64>}} when the result is not yet
 * ready; the guest validates the returned ID matches the allocated one and
 * parks the caller until the next `poll`. The host delivers completions as a
 * batch keyed by decimal ID strings: {"42":{"result":…}|{"error":…}, …}.
 * hyperlight_poll_pump() routes each entry to the matching parked op (see
 * hyperlight_hcall_deliver_batch), so the caller resumes with the real result
 * without replaying the request. Parking only happens when the caller is on a
 * parkable thread inside a poll pump. A malformed or mismatched yield sentinel
 * is always a protocol error (-8), never a silent park or raw pass-through.
 *
 * @param req          Request bytes (e.g. a JSON object).
 * @param req_len      Length of @req.
 * @param resp         Output buffer for the host response.
 * @param resp_cap     Capacity of @resp.
 * @param resp_len     Set to the number of bytes written to @resp on success.
 *
 * @return 0 on success, negative on failure:
 *         -1 no PEB / setup, -2 empty shared stacks,
 *         -3 FlatBuffer encode failed (request too large),
 *         -4 push to output_stack failed,
 *         -5 pop from input_stack failed,
 *         -6 FlatBuffer decode failed,
 *         -7 response buffer too small,
 *         -8 (CONFIG_HYPERLIGHT_POLL) yield sentinel has a malformed or
 *            mismatched numeric ID — protocol error,
 *         -9 (CONFIG_HYPERLIGHT_POLL) request ID allocation exhausted.
 */
int hyperlight_hcall(const __u8 *req, __sz req_len,
		     __u8 *resp, __sz resp_cap, __sz *resp_len);

#ifdef CONFIG_HYPERLIGHT_POLL
/* State of a non-blocking host call tracked by a struct hyperlight_hcall_op. */
enum {
	/* op->resp holds the final result; op->resp_len is its length. */
	HYPERLIGHT_HCALL_READY   = 0,
	/* The host reported the operation is still pending; op->request_id
	 * holds the guest-allocated ID used to match the completion batch entry.
	 */
	HYPERLIGHT_HCALL_PENDING = 1,
};

/**
 * A single in-flight (possibly-yielding) host function call.
 *
 * This is the building block for *multi-await*: a caller can submit several
 * host calls with hyperlight_hcall_submit() — each returns immediately with a
 * request ID rather than blocking — and then wait for any of them to complete
 * by driving hyperlight_hcall_poll() on each across successive host `poll`s.
 * The blocking hyperlight_hcall() is itself implemented as submit + park/poll
 * of a single op.
 *
 * The result buffer @resp is caller-owned and must outlive the op; the final
 * result lives there once the op is READY.
 */
struct hyperlight_hcall_op {
	__u8 *resp;		/* caller-owned result buffer */
	__sz  resp_cap;		/* capacity of @resp */
	__sz  resp_len;		/* bytes valid in @resp */
	__u64 request_id;	/* guest-allocated nonzero ID (0 = no batch lookup) */
	int   state;		/* HYPERLIGHT_HCALL_{READY,PENDING} */
	struct hyperlight_hcall_op *next; /* intrusive link, pending-op registry */
};

/**
 * Submit a host call without blocking.
 *
 * Allocates a monotone nonzero u64 request ID, wraps the request as
 * {"__hl_request_id":<id>,"request":<req>}, and issues it once. If the host
 * answers immediately, @op->state is HYPERLIGHT_HCALL_READY and the result is
 * in @resp. If the host yields ({"result":{"__hl_yield__":<id>}}), the
 * returned ID is validated against the allocated one; a mismatch or malformed
 * sentinel is an explicit protocol error (-8). On a valid yield @op->state is
 * HYPERLIGHT_HCALL_PENDING and the op is registered so a later
 * hyperlight_hcall_deliver_batch() can resolve it. Does NOT park, so it is
 * safe to call outside a poll pump and to submit several ops back-to-back
 * before waiting on any.
 *
 * @return 0 on success (check @op->state), negative on transport or protocol
 *         failure (see hyperlight_hcall return codes, including -8 and -9).
 */
int hyperlight_hcall_submit(struct hyperlight_hcall_op *op,
			    const __u8 *req, __sz req_len,
			    __u8 *resp, __sz resp_cap);

/**
 * Poll a pending op once, WITHOUT parking or issuing a host call.
 *
 * Completion is delivered out-of-band by hyperlight_hcall_deliver_batch() (from
 * the poll pump, using the JSON the host passes to the `poll` guest function),
 * which marks the op READY and copies the result into @op->resp. This function
 * merely reports the current state: the caller parks between polls (e.g. via
 * hyperlight_hcall_park_retry()) and re-checks after each host `poll`.
 *
 * @return 1 if now READY, 0 if still PENDING, negative on failure (-8 if
 *         the op is PENDING with no valid request ID).
 */
int hyperlight_hcall_poll(struct hyperlight_hcall_op *op);

/**
 * Deliver a batch of completed/errored host-call results to parked ops.
 *
 * @json is the JSON object the host passes as the `poll` guest function's
 * argument: {"<decimal-id>":{"result":…}|{"error":…}, …}. For every
 * registered PENDING op whose decimal request_id string appears as a key,
 * the corresponding value object is copied verbatim into the op's @resp
 * buffer, the op is marked READY and removed from the pending-op registry.
 * Ops whose IDs are absent stay pending. Called by hyperlight_poll_pump()
 * before it wakes parked callers.
 */
void hyperlight_hcall_deliver_batch(const __u8 *json, __sz json_len);
#endif /* CONFIG_HYPERLIGHT_POLL */

#ifdef __cplusplus
}
#endif

#endif /* __HYPERLIGHT_HCALL_H__ */
