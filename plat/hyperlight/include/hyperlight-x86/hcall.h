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
 * The request is carried in a versioned binary control frame with a
 * guest-allocated nonzero u64 ID (static guest memory, preserved across
 * snapshots). A pending response parks the caller until a later binary `poll`
 * batch delivers the final JSON result for that ID.
 * hyperlight_poll_pump() routes each entry to the matching parked op (see
 * hyperlight_hcall_deliver_batch), so the caller resumes with the real result
 * without replaying the request. Parking only happens when the caller is on a
 * parkable thread inside a poll pump. A malformed frame or mismatched ID is
 * always a protocol error (-8).
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
 *         -8 malformed async control frame, mismatched request ID,
 *            or pending result outside a poll pump.
 */
int hyperlight_hcall(const __u8 *req, __sz req_len,
		     __u8 *resp, __sz resp_cap, __sz *resp_len);

/**
 * Deliver a batch of completed/errored host-call results to parked ops.
 *
 * @frame is the binary byte vector passed to the guest `poll` function. Each
 * entry contains a numeric request ID and a length-delimited JSON result.
 * Matching callers are woken; IDs absent from the batch stay pending.
 */
void hyperlight_hcall_deliver_batch(const __u8 *frame, __sz frame_len);

#ifdef __cplusplus
}
#endif

#endif /* __HYPERLIGHT_HCALL_H__ */
