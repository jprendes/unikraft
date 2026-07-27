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
 * {"__hl_request_id":"<16 lowercase hex digits>","request":<original>} before
 * sending; the underlying u64 is a guest-allocated monotonically incrementing
 * nonzero ID (static guest memory, preserved across snapshots). The host echoes
 * the string as {"result":{"__hl_yield__":"<16 lowercase hex digits>"}} when
 * the result is not yet ready; the guest validates the returned ID matches the
 * allocated one and parks the caller until the next `poll`. The host delivers
 * completions in a batch keyed by the same fixed-width hex strings.
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
 *            mismatched hexadecimal ID — protocol error.
 */
int hyperlight_hcall(const __u8 *req, __sz req_len,
		     __u8 *resp, __sz resp_cap, __sz *resp_len);

#ifdef CONFIG_HYPERLIGHT_POLL
/**
 * Deliver a batch of completed/errored host-call results to parked ops.
 *
 * @json is the JSON object the host passes as the `poll` guest function's
 * argument: {"<16-digit-hex-id>":{"result":…}|{"error":…}, …}. For every
 * registered op whose hexadecimal request_id string appears as a key,
 * the corresponding value object remains in a stable batch snapshot and the
 * matching caller is woken. Ops whose IDs are absent stay pending.
 */
void hyperlight_hcall_deliver_batch(const __u8 *json, __sz json_len);
#endif /* CONFIG_HYPERLIGHT_POLL */

#ifdef __cplusplus
}
#endif

#endif /* __HYPERLIGHT_HCALL_H__ */
