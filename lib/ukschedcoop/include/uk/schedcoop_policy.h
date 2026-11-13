/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2026, Unikraft GmbH and The Unikraft Authors. */

#ifndef __UK_SCHEDCOOP_POLICY_H__
#define __UK_SCHEDCOOP_POLICY_H__

#include <stdbool.h>
#include <uk/event.h>

struct uk_thread;

/* Handlers may reject a thread for this scheduling pass. They must not
 * allocate, block, fail, or make an already rejected thread eligible.
 * The same policy applies to runnable threads and sleeping-thread deadlines.
 */
struct uk_schedcoop_eligibility_event_data {
	const struct uk_thread *thread;
	bool eligible;
};

#endif
