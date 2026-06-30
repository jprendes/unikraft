/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2024, Unikraft GmbH and The Unikraft Authors.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

#include <stdint.h>
#include <uk/arch/ctx.h>
#include <uk/assert.h>
#include <uk/lcpu.h>

void uk_lcpu_enable_irq(void)
{
	local_irq_enable();
}

void uk_lcpu_disable_irq(void)
{
	local_irq_disable();
}

unsigned long uk_lcpu_save_irqf(void)
{
	unsigned long flags;

	local_irq_save(flags);

	return flags;
}

void uk_lcpu_restore_irqf(unsigned long flags)
{
	local_irq_restore(flags);
}

int uk_lcpu_irqs_disabled(void)
{
	return irqs_disabled();
}

void uk_lcpu_irqs_handle_pending(void)
{

}

void uk_lcpu_set_auxsp(__uptr auxsp)
{
	struct uk_lcpu *lcpu = uk_lcpu_get_current();
	struct ukarch_auxspcb *auxspcb;

	UK_ASSERT(IS_LCPU_PTR(rdgsbase()));

	lcpu->auxsp = auxsp;
	auxspcb = ukarch_auxsp_get_cb(auxsp);
	ukarch_sysctx_set_gsbase(&auxspcb->uksysctx, (__uptr)lcpu);
}

__uptr uk_lcpu_get_auxsp(void)
{
	UK_ASSERT(IS_LCPU_PTR(uk_lcpu_get_current()));
	return uk_lcpu_get_current()->auxsp;
}

__isr __uptr ukplat_lcpu_get_auxsp_in_except(void)
{
	return lcpu_get_current_in_except()->auxsp;
}
