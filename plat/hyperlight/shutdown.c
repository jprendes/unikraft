/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2024, Unikraft GmbH and The Unikraft Authors.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

#include <uk/pm.h>
#include <uk/boot.h>
#include <uk/print.h>
#include <uk/plat/common/bootinfo.h>

#include <hyperlight-x86/outb.h>
#include <hyperlight-x86/dispatch.h>

#ifdef CONFIG_HYPERLIGHT_HCALL
#include <uk/lcpu.h>
#include <uk/plat/time.h>
#include <uk/plat/common/_time.h>
#endif

/* Push void result to the output buffer before halting.
 * This is needed because the application exits via uk_pm_shutdown,
 * bypassing the dispatch stub's output buffer push.
 */
extern void hyperlight_dispatch_push_void_result(void);

static int hyperlight_halt(void)
{
	hyperlight_dispatch_push_void_result();

	__u64 dispatch_addr = (__u64)hyperlight_dispatch_function;

	/* Move RSP to scratch stack (always writable, even after restore).
	 * Put dispatch address in RAX, halt via port 108.
	 */
	__asm__ volatile(
		"movabs $0xFFFFFFFFFFFFEFE0, %%rsp\n\t"
		"movq %0, %%rax\n\t"
		"movw $108, %%dx\n\t"
		"outl %%eax, %%dx\n\t"
		"cli\n\t"
		"hlt\n\t"
		: : "r"(dispatch_addr) : "rax", "rdx", "rsp"
	);
	__builtin_unreachable();
}

static int hyperlight_crash(void)
{
	hyperlight_abort(0xFF);
	__builtin_unreachable();
}

#ifdef CONFIG_HYPERLIGHT_HCALL
static void hyperlight_halt_irq(void)
{
	time_block_until((__snsec)ukplat_monotonic_clock() + 1000000000LL);
}
#endif

static const struct uk_pm_ops hyperlight_pm_ops = {
	.syshalt = hyperlight_halt,
	.sysrestart = hyperlight_halt,
	.syscrash = hyperlight_crash,
};

#ifdef CONFIG_HYPERLIGHT_HCALL
static const struct uk_lcpu_pm_ops hyperlight_lcpu_pm_ops = {
	.halt_irq = hyperlight_halt_irq,
};
#endif

int hyperlight_register_pm_ops(struct ukplat_bootinfo __unused *bi)
{
	int rc = uk_pm_ops_register(&hyperlight_pm_ops);
	return rc;
}

#ifdef CONFIG_HYPERLIGHT_HCALL
void hyperlight_register_lcpu_pm_ops(void)
{
	uk_lcpu_pm_ops_register(&hyperlight_lcpu_pm_ops);
}
#endif

UK_BOOT_EARLYTAB_ENTRY(hyperlight_register_pm_ops, UK_PRIO_EARLIEST);
