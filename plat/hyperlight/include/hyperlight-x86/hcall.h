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
 * Under CONFIG_HYPERLIGHT_POLL, if the host reports the result is not ready
 * yet, this function transparently suspends the caller until the next host
 * `poll` delivers the result; the caller observes only the final result. The
 * "not ready" signal is a yield sentinel carrying an opaque completion token:
 * the tool returns json!({"__hl_yield__": "<token>"}), delivered as the payload
 * {"result":{"__hl_yield__":"<token>"}}. The guest does not interpret the
 * token; it registers the parked op under it and waits. On every subsequent
 * host `poll`, the host passes a JSON object of all tasks that have completed
 * or errored — {"<token>":{"result":…}|{"error":…}, …} — as the poll
 * function's string argument. hyperlight_poll_pump() routes each entry to the
 * matching parked op (see hyperlight_hcall_deliver_batch), so the caller
 * resumes with the real result without ever issuing a follow-up host call.
 * Using a token — rather than replaying the original request — means the host
 * is never asked to re-execute a non-idempotent operation, and distinct
 * concurrently-parked callers are disambiguated by their tokens. Parking only
 * happens when the caller is on a parkable thread inside a poll pump;
 * otherwise the sentinel is returned to the caller unchanged.
 *
 * By contract the token is an opaque JSON string with no characters requiring
 * JSON escaping (no '"' or '\\') and at most 512 bytes.
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
 *         -8 yield completion token too large to poll (> 512 bytes).
 */
int hyperlight_hcall(const __u8 *req, __sz req_len,
		     __u8 *resp, __sz resp_cap, __sz *resp_len);

#ifdef CONFIG_HYPERLIGHT_POLL
/* Opaque completion-token size bound (see hyperlight_hcall above). Host-chosen
 * tokens must fit; 512 bytes is generous for a base64/uuid/counter handle.
 */
#define HYPERLIGHT_HCALL_TOKEN_MAX 512

/* State of a non-blocking host call tracked by a struct hyperlight_hcall_op. */
enum {
	/* op->resp holds the final result; op->resp_len is its length. */
	HYPERLIGHT_HCALL_READY   = 0,
	/* The host reported the operation is still pending. op->token holds the
	 * opaque completion token to poll (unless op->token_len == 0, meaning
	 * the token was too large to poll — a subsequent poll returns -8).
	 */
	HYPERLIGHT_HCALL_PENDING = 1,
};

/**
 * A single in-flight (possibly-yielding) host function call.
 *
 * This is the building block for *multi-await*: a caller can submit several
 * host calls with hyperlight_hcall_submit() — each returns immediately with a
 * completion token rather than blocking — and then wait for any of them to
 * complete by driving hyperlight_hcall_poll() on each across successive host
 * `poll`s. The blocking hyperlight_hcall() is itself implemented as
 * submit + park/poll of a single op.
 *
 * The result buffer @resp is caller-owned and must outlive the op; the final
 * result (or the latest yield sentinel while pending) lives there.
 */
struct hyperlight_hcall_op {
	__u8 *resp;		/* caller-owned result buffer */
	__sz  resp_cap;		/* capacity of @resp */
	__sz  resp_len;		/* bytes valid in @resp */
	__sz  token_len;	/* length of @token (0 = pending-but-unpollable) */
	int   state;		/* HYPERLIGHT_HCALL_{READY,PENDING} */
	struct hyperlight_hcall_op *next; /* intrusive link, pending-op registry */
	__u8  token[HYPERLIGHT_HCALL_TOKEN_MAX];
};

/**
 * Submit a host call without blocking.
 *
 * Issues the request once. If the host answers immediately, @op->state is set
 * to HYPERLIGHT_HCALL_READY and the result is in @resp. If the host yields, the
 * completion token is captured into @op, @op->state is HYPERLIGHT_HCALL_PENDING
 * and the op is registered in the pending-op registry so a later
 * hyperlight_hcall_deliver_batch() can resolve it. Does NOT park, so it is safe
 * to call outside a poll pump and to submit several ops back-to-back before
 * waiting on any.
 *
 * @return 0 on success (check @op->state), negative on transport failure (see
 *         hyperlight_hcall return codes).
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
 * @return 1 if now READY, 0 if still PENDING, negative on failure (-8 if the
 *         token was too large to poll).
 */
int hyperlight_hcall_poll(struct hyperlight_hcall_op *op);

/**
 * Deliver a batch of completed/errored host-call results to parked ops.
 *
 * @json is the JSON object the host passes as the `poll` guest function's
 * argument: {"<token>":{"result":…}|{"error":…}, …}. For every registered
 * PENDING op whose token appears as a key, the corresponding value object is
 * copied verbatim into the op's @resp buffer, the op is marked READY and
 * removed from the pending-op registry. Ops whose tokens are absent stay
 * pending. Called by hyperlight_poll_pump() before it wakes parked callers.
 */
void hyperlight_hcall_deliver_batch(const __u8 *json, __sz json_len);
#endif /* CONFIG_HYPERLIGHT_POLL */

#ifdef __cplusplus
}
#endif

#endif /* __HYPERLIGHT_HCALL_H__ */
