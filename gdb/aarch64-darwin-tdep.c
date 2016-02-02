#include "defs.h"

#include "gdbarch.h"
#include "glibc-tdep.h"
#include "linux-tdep.h"
#include "aarch64-tdep.h"
#include "osabi.h"
#include "solib-darwin.h"
#include "symtab.h"
#include "tramp-frame.h"
#include "trad-frame.h"

#include "inferior.h"
#include "regcache.h"
#include "regset.h"

#include "cli/cli-utils.h"
#include "stap-probe.h"
#include "parser-defs.h"
#include "user-regs.h"
#include "xml-syscall.h"
#include <ctype.h>
#include "solib.h"
#include "gdb_bfd.h"
#include "gdbcore.h"
#include "gdbthread.h"
#include "breakpoint.h"
#include "solist.h"

#include <mach/mach.h>

/*
 * GDB is killing me!
 * Do not include <mach-o/loader.h>
 * this will include ../include/mach-o/loader.h of GDB!!
 * have to copy some struct here. tears~~
 * */
/*
 * The 32-bit mach header appears at the very beginning of the object file for
 * 32-bit architectures.
 */
struct mach_header {
	uint32_t	magic;		/* mach magic number identifier */
	cpu_type_t	cputype;	/* cpu specifier */
	cpu_subtype_t	cpusubtype;	/* machine specifier */
	uint32_t	filetype;	/* type of file */
	uint32_t	ncmds;		/* number of load commands */
	uint32_t	sizeofcmds;	/* the size of all the load commands */
	uint32_t	flags;		/* flags */
};

/* Constant for the magic field of the mach_header (32-bit architectures) */
#define	MH_MAGIC	0xfeedface	/* the mach magic number */
#define MH_CIGAM	0xcefaedfe	/* NXSwapInt(MH_MAGIC) */

/*
 * The 64-bit mach header appears at the very beginning of object files for
 * 64-bit architectures.
 */
struct mach_header_64 {
	uint32_t	magic;		/* mach magic number identifier */
	cpu_type_t	cputype;	/* cpu specifier */
	cpu_subtype_t	cpusubtype;	/* machine specifier */
	uint32_t	filetype;	/* type of file */
	uint32_t	ncmds;		/* number of load commands */
	uint32_t	sizeofcmds;	/* the size of all the load commands */
	uint32_t	flags;		/* flags */
	uint32_t	reserved;	/* reserved */
};

/* Constant for the magic field of the mach_header_64 (64-bit architectures) */
#define MH_MAGIC_64 0xfeedfacf /* the 64-bit mach magic number */
#define MH_CIGAM_64 0xcffaedfe /* NXSwapInt(MH_MAGIC_64) */

/*
 * The load commands directly follow the mach_header.  The total size of all
 * of the commands is given by the sizeofcmds field in the mach_header.  All
 * load commands must have as their first two fields cmd and cmdsize.  The cmd
 * field is filled in with a constant for that command type.  Each command type
 * has a structure specifically for it.  The cmdsize field is the size in bytes
 * of the particular load command structure plus anything that follows it that
 * is a part of the load command (i.e. section structures, strings, etc.).  To
 * advance to the next load command the cmdsize can be added to the offset or
 * pointer of the current load command.  The cmdsize for 32-bit architectures
 * MUST be a multiple of 4 bytes and for 64-bit architectures MUST be a multiple
 * of 8 bytes (these are forever the maximum alignment of any load commands).
 * The padded bytes must be zero.  All tables in the object file must also
 * follow these rules so the file can be memory mapped.  Otherwise the pointers
 * to these tables will not work well or at all on some machines.  With all
 * padding zeroed like objects will compare byte for byte.
 */
struct load_command {
	uint32_t cmd;		/* type of load command */
	uint32_t cmdsize;	/* total size of command in bytes */
};

/* Constants for the cmd field of all load commands, the type */
#define	LC_SEGMENT	0x1	/* segment of this file to be mapped */
#define	LC_SYMTAB	0x2	/* link-edit stab symbol table info */
#define	LC_SYMSEG	0x3	/* link-edit gdb symbol table info (obsolete) */
#define	LC_THREAD	0x4	/* thread */
#define	LC_UNIXTHREAD	0x5	/* unix thread (includes a stack) */
#define	LC_LOADFVMLIB	0x6	/* load a specified fixed VM shared library */
#define	LC_IDFVMLIB	0x7	/* fixed VM shared library identification */
#define	LC_IDENT	0x8	/* object identification info (obsolete) */
#define LC_FVMFILE	0x9	/* fixed VM file inclusion (internal use) */
#define LC_PREPAGE      0xa     /* prepage command (internal use) */
#define	LC_DYSYMTAB	0xb	/* dynamic link-edit symbol table info */
#define	LC_LOAD_DYLIB	0xc	/* load a dynamically linked shared library */
#define	LC_ID_DYLIB	0xd	/* dynamically linked shared lib ident */
#define LC_LOAD_DYLINKER 0xe	/* load a dynamic linker */
#define LC_ID_DYLINKER	0xf	/* dynamic linker identification */
#define	LC_PREBOUND_DYLIB 0x10	/* modules prebound for a dynamically */
				/*  linked shared library */
#define	LC_ROUTINES	0x11	/* image routines */
#define	LC_SUB_FRAMEWORK 0x12	/* sub framework */
#define	LC_SUB_UMBRELLA 0x13	/* sub umbrella */
#define	LC_SUB_CLIENT	0x14	/* sub client */
#define	LC_SUB_LIBRARY  0x15	/* sub library */
#define	LC_TWOLEVEL_HINTS 0x16	/* two-level namespace lookup hints */
#define	LC_PREBIND_CKSUM  0x17	/* prebind checksum */
#define	LC_SEGMENT_64	0x19	/* 64-bit segment of this file to be
				   mapped */
#define	LC_ROUTINES_64	0x1a	/* 64-bit image routines */

/*
 * The segment load command indicates that a part of this file is to be
 * mapped into the task's address space.  The size of this segment in memory,
 * vmsize, maybe equal to or larger than the amount to map from this file,
 * filesize.  The file is mapped starting at fileoff to the beginning of
 * the segment in memory, vmaddr.  The rest of the memory of the segment,
 * if any, is allocated zero fill on demand.  The segment's maximum virtual
 * memory protection and initial virtual memory protection are specified
 * by the maxprot and initprot fields.  If the segment has sections then the
 * section structures directly follow the segment command and their size is
 * reflected in cmdsize.
 */
struct segment_command { /* for 32-bit architectures */
	uint32_t	cmd;		/* LC_SEGMENT */
	uint32_t	cmdsize;	/* includes sizeof section structs */
	char		segname[16];	/* segment name */
	uint32_t	vmaddr;		/* memory address of this segment */
	uint32_t	vmsize;		/* memory size of this segment */
	uint32_t	fileoff;	/* file offset of this segment */
	uint32_t	filesize;	/* amount to map from the file */
	vm_prot_t	maxprot;	/* maximum VM protection */
	vm_prot_t	initprot;	/* initial VM protection */
	uint32_t	nsects;		/* number of sections in segment */
	uint32_t	flags;		/* flags */
};

/*
 * The 64-bit segment load command indicates that a part of this file is to be
 * mapped into a 64-bit task's address space.  If the 64-bit segment has
 * sections then section_64 structures directly follow the 64-bit segment
 * command and their size is reflected in cmdsize.
 */
struct segment_command_64 { /* for 64-bit architectures */
	uint32_t	cmd;		/* LC_SEGMENT_64 */
	uint32_t	cmdsize;	/* includes sizeof section_64 structs */
	char		segname[16];	/* segment name */
	uint64_t	vmaddr;		/* memory address of this segment */
	uint64_t	vmsize;		/* memory size of this segment */
	uint64_t	fileoff;	/* file offset of this segment */
	uint64_t	filesize;	/* amount to map from the file */
	vm_prot_t	maxprot;	/* maximum VM protection */
	vm_prot_t	initprot;	/* initial VM protection */
	uint32_t	nsects;		/* number of sections in segment */
	uint32_t	flags;		/* flags */
};


static int
aarch64_stap_is_single_operand (struct gdbarch *gdbarch, const char *s)
{
  return (*s == '#' || isdigit (*s) /* Literal number.  */
	  || *s == '[' /* Register indirection.  */
	  || isalpha (*s)); /* Register value.  */
}

/* This routine is used to parse a special token in AArch64's assembly.

   The special tokens parsed by it are:

      - Register displacement (e.g, [fp, #-8])

   It returns one if the special token has been parsed successfully,
   or zero if the current token is not considered special.  */

static int
aarch64_stap_parse_special_token (struct gdbarch *gdbarch,
				  struct stap_parse_info *p)
{
  if (*p->arg == '[')
    {
      /* Temporary holder for lookahead.  */
      const char *tmp = p->arg;
      char *endp;
      /* Used to save the register name.  */
      const char *start;
      char *regname;
      int len;
      int got_minus = 0;
      long displacement;
      struct stoken str;

      ++tmp;
      start = tmp;

      /* Register name.  */
      while (isalnum (*tmp))
	++tmp;

      if (*tmp != ',')
	return 0;

      len = tmp - start;
      regname = alloca (len + 2);

      strncpy (regname, start, len);
      regname[len] = '\0';

      if (user_reg_map_name_to_regnum (gdbarch, regname, len) == -1)
	error (_("Invalid register name `%s' on expression `%s'."),
	       regname, p->saved_arg);

      ++tmp;
      tmp = skip_spaces_const (tmp);
      /* Now we expect a number.  It can begin with '#' or simply
	 a digit.  */
      if (*tmp == '#')
	++tmp;

      if (*tmp == '-')
	{
	  ++tmp;
	  got_minus = 1;
	}
      else if (*tmp == '+')
	++tmp;

      if (!isdigit (*tmp))
	return 0;

      displacement = strtol (tmp, &endp, 10);
      tmp = endp;

      /* Skipping last `]'.  */
      if (*tmp++ != ']')
	return 0;

      /* The displacement.  */
      write_exp_elt_opcode (&p->pstate, OP_LONG);
      write_exp_elt_type (&p->pstate, builtin_type (gdbarch)->builtin_long);
      write_exp_elt_longcst (&p->pstate, displacement);
      write_exp_elt_opcode (&p->pstate, OP_LONG);
      if (got_minus)
	write_exp_elt_opcode (&p->pstate, UNOP_NEG);

      /* The register name.  */
      write_exp_elt_opcode (&p->pstate, OP_REGISTER);
      str.ptr = regname;
      str.length = len;
      write_exp_string (&p->pstate, str);
      write_exp_elt_opcode (&p->pstate, OP_REGISTER);

      write_exp_elt_opcode (&p->pstate, BINOP_ADD);

      /* Casting to the expected type.  */
      write_exp_elt_opcode (&p->pstate, UNOP_CAST);
      write_exp_elt_type (&p->pstate, lookup_pointer_type (p->arg_type));
      write_exp_elt_opcode (&p->pstate, UNOP_CAST);

      write_exp_elt_opcode (&p->pstate, UNOP_IND);

      p->arg = tmp;
    }
  else
    return 0;

  return 1;
}

static CORE_ADDR aarch64_darwin_skip_prologue (struct gdbarch *gdbarch, CORE_ADDR pc)
{
	return pc;
}

static void aarch64_darwin_init_abi (struct gdbarch_info info, struct gdbarch *gdbarch)
{
	static const char *const stap_integer_prefixes[] = { "#", "", NULL };
	static const char *const stap_register_prefixes[] = { "", NULL };
	static const char *const stap_register_indirection_prefixes[] = { "[",
		NULL };
	static const char *const stap_register_indirection_suffixes[] = { "]",
		NULL };
	struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

	tdep->lowest_pc = 0x8000;

	//TODO: linux_init_abi (info, gdbarch);

	/* TODO: Enable longjmp.  */
	tdep->jb_pc = -1;

	/* SystemTap related.  */
	set_gdbarch_stap_integer_prefixes (gdbarch, stap_integer_prefixes);
	set_gdbarch_stap_register_prefixes (gdbarch, stap_register_prefixes);
	set_gdbarch_stap_register_indirection_prefixes (gdbarch, stap_register_indirection_prefixes);
	set_gdbarch_stap_register_indirection_suffixes (gdbarch, stap_register_indirection_suffixes);
	set_gdbarch_stap_is_single_operand (gdbarch, aarch64_stap_is_single_operand);
	set_gdbarch_stap_parse_special_token (gdbarch, aarch64_stap_parse_special_token);

	/* do NOT pass prologue */
	set_gdbarch_skip_prologue (gdbarch, aarch64_darwin_skip_prologue);

	/* Reversible debugging, process record.  */
	set_gdbarch_process_record (gdbarch, aarch64_process_record);
	/* TODO: Syscall record.  */
	// tdep->aarch64_syscall_record = aarch64_darwin_syscall_record;

	set_solib_ops (gdbarch, &darwin_so_ops);
}

static enum gdb_osabi aarch64_mach_o_osabi_sniffer (bfd *abfd)
{
    if (!bfd_check_format (abfd, bfd_object))
	return GDB_OSABI_UNKNOWN;

    if (bfd_get_arch (abfd) == bfd_arch_aarch64)
	return GDB_OSABI_DARWIN;

    return GDB_OSABI_UNKNOWN;
}

struct darwin_dyld_metric
{
	uint64_t base, size, origbase;
};

static kern_return_t find_dyld_metric(uint64_t hintaddr, uint64_t * base, uint64_t * textsize, uint64_t * origbase)
{
	const size_t pgsz =  getpagesize();
	uint64_t dyldbase = hintaddr & ~(pgsz-1);
	char * buf = (char*) malloc(pgsz);
	int i;
	kern_return_t ret = KERN_FAILURE;

	for (;;)
	{
		if (target_read_memory(dyldbase, (gdb_byte*) buf, pgsz))
		{
			ret = KERN_FAILURE;
			goto retpos;
		}
		struct mach_header * mh = (struct mach_header*)buf;
		if (mh->magic == MH_MAGIC || mh->magic == MH_MAGIC_64)
		{
			//find base, contintue to find size.
			size_t hsz = (mh->magic==MH_MAGIC_64) ?  sizeof(struct mach_header_64) : sizeof(struct mach_header);
			struct load_command * lc = (struct load_command*) (buf + hsz);

			for (i=0; i<mh->ncmds; ++i)
			{
				if (lc->cmd == LC_SEGMENT)
				{
					struct segment_command * sc = (struct segment_command*)lc;
					if (sc->vmaddr == 0) continue;
					*base = dyldbase;
					*textsize = sc->vmsize;
					*origbase = sc->vmaddr;
					ret = KERN_SUCCESS;
					goto retpos;
				}
				else if (lc->cmd == LC_SEGMENT_64)
				{
					struct segment_command_64 * sc = (struct segment_command_64*)lc;
					if (sc->vmaddr == 0) continue;
					*base = dyldbase;
					*textsize = sc->vmsize;
					*origbase = sc->vmaddr;
					ret = KERN_SUCCESS;
					goto retpos;
				}
				lc = (struct load_command*) ((char*)lc + lc->cmdsize);
			}

			ret = KERN_INVALID_OBJECT;
			goto retpos;
		}
		dyldbase -= pgsz;
	}
retpos:
	free(buf);
	return ret;
}

extern void (*darwin_adjust_image_notifier) (uint64_t * notifier);

static void darwin_adjust_image_notifier_(uint64_t * notifier)
{
    uint64_t pc = regcache_read_pc (get_current_regcache ());
	struct darwin_dyld_metric dm;

	gdb_assert(notifier != 0);

	find_dyld_metric(pc, &dm.base, &dm.size, &dm.origbase);
	*notifier = *notifier - dm.origbase + dm.base;

	//set a break point at first location.
	char pos[32];
	sprintf(pos, "*%#llx\n", (long long)pc);
	tbreak_command(pos, 0);
}

extern initialize_file_ftype _initialize_aarch64_darwin_tdep;

/* -Wmissing-prototypes */
void //note: _initialize_ must at begin of line.
_initialize_aarch64_darwin_tdep (void)
{
	darwin_adjust_image_notifier = darwin_adjust_image_notifier_;
	gdbarch_register_osabi_sniffer (bfd_arch_unknown, bfd_target_mach_o_flavour, aarch64_mach_o_osabi_sniffer);
	//register_gdbarch_init (bfd_arch_aarch64, aarch64_gdbarch_init);
	gdbarch_register_osabi (bfd_arch_aarch64, bfd_mach_aarch64, GDB_OSABI_DARWIN, aarch64_darwin_init_abi);
}
