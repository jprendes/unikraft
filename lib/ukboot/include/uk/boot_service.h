/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2026, Unikraft GmbH and The Unikraft Authors. */

#ifndef __UK_BOOT_SERVICE_H__
#define __UK_BOOT_SERVICE_H__

#include <stdbool.h>
#include <uk/event.h>

/* UKBOOT_INIT_START_EVENT runs in the initialized POSIX init process.
 * A service can request standalone mode: do not start the application or
 * shut down when the child list becomes empty. Startup errors are fatal.
 * UKBOOT_INIT_STOP_EVENT runs before init returns and must not fail.
 */
struct uk_boot_service_event_data {
	bool standalone;
};

#endif
