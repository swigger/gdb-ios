#include "defs.h"
#include "frame.h"
#include "inferior.h"
#include "target.h"
#include "symfile.h"
#include "symtab.h"
#include "objfiles.h"
#include "gdbcmd.h"
#include "regcache.h"
#include "gdbarch.h"
#include "arch-utils.h"
#include "gdbcore.h"

#include "darwin-nat.h"
#include "aarch64-tdep.h"

void darwin_set_sstep (thread_t thread, int enable)
{
	//TODO: check we're at sig return...
	//struct aarch64_darwin_debug_state regs;
	arm_debug_state64_t regs;
	unsigned int count =  ARM_DEBUG_STATE64_COUNT; //sizeof(regs) / sizeof(uint32_t);
	kern_return_t kret;

	kret = thread_get_state(thread, ARM_DEBUG_STATE64, (thread_state_t)& regs, &count);
	if (kret != KERN_SUCCESS)
	{
		printf_unfiltered (_("darwin_set_sstep: error %x, thread=%x\n"), kret, thread);
		return;
	}
	if (enable)
		regs.__mdscr_el1 |= 1;
	else
		regs.__mdscr_el1 &= ~ (uint64_t)1;
	kret = thread_set_state(thread, ARM_DEBUG_STATE64, (thread_state_t)& regs, count);
	if (kret != KERN_SUCCESS)
	{
		printf_unfiltered (_("darwin_set_sstep: error %x, thread=%x\n"), kret, thread);
		return;
	}
	return ; //with ok state.
}

void darwin_check_osabi (darwin_inferior *inf, thread_t thread)
{
	if (gdbarch_osabi (target_gdbarch ()) == GDB_OSABI_UNKNOWN)
	{
		/* Attaching to a process.  Let's figure out what kind it is.  */
		arm_thread_state64_t gp_regs;
		struct gdbarch_info info;
		unsigned int gp_count = ARM_THREAD_STATE64_COUNT;
		kern_return_t ret;

		ret = thread_get_state (thread, ARM_THREAD_STATE64, (thread_state_t) &gp_regs, &gp_count);
		if (ret != KERN_SUCCESS)
		{
			MACH_CHECK_ERROR (ret);
			return;
		}

		gdbarch_info_init (&info);
		gdbarch_info_fill (&info);
		info.byte_order = gdbarch_byte_order (target_gdbarch ());
		info.osabi = GDB_OSABI_DARWIN;
		info.bfd_arch_info = bfd_lookup_arch (bfd_arch_aarch64, bfd_mach_aarch64);
		gdbarch_update_p (info);
	}
}

static void aarch64_darwin_fetch_inferior_registers(struct target_ops *ops, struct regcache *regcache, int regno)
{
	thread_t current_thread = ptid_get_tid(inferior_ptid);
	int fetched = 0;
	int i;
	struct gdbarch *gdbarch = get_regcache_arch (regcache);

	if (gdbarch_ptr_bit (gdbarch) != 64)
	{
		warning("internal error: invalid pionter size\n");
		return ;
	}

	kern_return_t ret;
	{
		arm_thread_state64_t gp_regs;
		unsigned int gp_count = ARM_THREAD_STATE64_COUNT;

		ret = thread_get_state (current_thread, ARM_THREAD_STATE64, (thread_state_t) &gp_regs, &gp_count);
		if (ret == KERN_SUCCESS)
		{
			for (i = AARCH64_X0_REGNUM; i <= AARCH64_CPSR_REGNUM; ++i)
				regcache_raw_supply(regcache, i, (char *) &gp_regs.__x[i - AARCH64_X0_REGNUM]);
		}
		else
		{
			printf_unfiltered (_("Error calling thread_get_state for GP registers for thread 0x%lx\n"),
					(unsigned long) current_thread);
			MACH_CHECK_ERROR (ret);
			warning (_("unknown register %d"), regno);
			regcache_raw_supply (regcache, regno, NULL);
		}
	}
}

static void aarch64_darwin_store_inferior_registers (struct target_ops *ops, struct regcache *regcache, int regno)
{
	int i;
	thread_t current_thread = ptid_get_tid (inferior_ptid);
	struct gdbarch *gdbarch = get_regcache_arch (regcache);

	if (gdbarch_ptr_bit (gdbarch) != 64)
	{
		warning("internal error: invalid pionter size\n");
		return ;
	}

	kern_return_t ret;
	{
		arm_thread_state64_t gp_regs;
		unsigned int gp_count = ARM_THREAD_STATE64_COUNT;

		ret = thread_get_state (current_thread, ARM_THREAD_STATE64, (thread_state_t) &gp_regs, &gp_count);
		MACH_CHECK_ERROR(ret);
		gdb_assert (gp_count == ARM_THREAD_STATE64_COUNT);

		for (i = AARCH64_X0_REGNUM; i <= AARCH64_CPSR_REGNUM; ++i)
		{
			if (regno == -1 || regno == i)
			{
				regcache_raw_collect(regcache, i, (char *) &gp_regs.__x[i - AARCH64_X0_REGNUM]);
			}
		}
		ret = thread_set_state (current_thread, ARM_THREAD_STATE64, (thread_state_t) &gp_regs, gp_count);
		MACH_CHECK_ERROR(ret);
	}
}

/* Support for debug registers, boosted mostly from i386-linux-nat.c.  */
void darwin_complete_target (struct target_ops *target)
{
	//amd64_native_gregset64_reg_offset = amd64_darwin_thread_state_reg_offset;
	//x86_use_watchpoints (target);
	target->to_fetch_registers = aarch64_darwin_fetch_inferior_registers;
	target->to_store_registers = aarch64_darwin_store_inferior_registers;
}
