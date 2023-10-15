// {binary-executable-copy}.c
//
// Author: Noah BEAUFILS
// Date: 14-oct-2023
// From: [Copyright (C) 2002, 2003 Dion Mendel.]

/* Note:	Does not work for suid apps under linux 2.2.x.
			Does not work on linux kernels between 2.4.21-pre6 .. 2.4.21-rc2
			due to an incorrect ptrace patch being applied to those kernels.
*/

/* ============================ HEADER ============================ */

/* only if there is a "elf.h" in the system */
#define HAVE_ELF_H

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <signal.h>

#define bool		short
#define true		1
#define false		0
#define BUFF_SIZE	1024

#ifdef HAVE_ELF_H
	#include <elf.h>
#endif

#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __FreeBSD__
	#define PTRACE_PEEKTEXT PT_READ_I
	#define PTRACE_PEEKDATA PT_READ_D
	#define PTRACE_TRACEME  PT_TRACE_ME
	#define PTRACE_KILL     PT_KILL
#endif /* __FreeBSD__ */

/* -----------------------   elf definition   ---------------------- */

#ifndef HAVE_ELF_H

/* define Types */
typedef u_int16_t Elf32_Half; // type for 16-bit quantitie
typedef u_int32_t Elf32_Word; // type for 32-bit quantitie
typedef u_int32_t Elf32_Addr; // type for address
typedef u_int32_t Elf32_Off; // Type for file offsets

/* The ELF file header (present at the start of file) contains metadate about the file */

# define EI_NIDENT (16)
/* size for e_ident witch identifie the file as ELF (begin by "0x7FELF") */

typedef struct {

	unsigned char	e_ident[EI_NIDENT];		/* class of file (32 or 64 bits) and endianness) */
	Elf32_Half		e_type;					/* information about file type */
	Elf32_Half		e_machine;				/* Architecture (x86, ARM, ...) */
	Elf32_Word		e_version;				/* ELF file version */

	/* these variable's size depends of the class file (32 or 64 bits) */

	Elf32_Addr		e_entry;				/* Entry point virtual address */
	Elf32_Off		e_phoff;				/* Program header table file offset */
	Elf32_Off		e_shoff;				/* Section header table file offset */

	Elf32_Word		e_flags;				/* Processor-specific flags */
	Elf32_Half		e_ehsize;               /* ELF header size in bytes */
	Elf32_Half		e_phentsize;			/* Program header table entry size */
	Elf32_Half		e_phnum;				/* Program header table entry count */
	Elf32_Half		e_shentsize;			/* Section header table entry size */
	Elf32_Half		e_shnum;				/* Section header table entry count */
	Elf32_Half		e_shstrndx;				/* Section header string table index */

}	Elf32_Ehdr;

# define EI_CLASS	4 // index of file class in e_ident[]
# define ELFCLASS32	1 // indicate that the file is a 32-bit objects

/* Legal values for e_type */
# define ET_NONE	0 // no specific type (unfinished or temporary file)
# define ET_REL		1 // Relocatable object file
# define ET_EXEC	2 // Executable file
# define ET_DYN		3 // Shared object file
/* [ ... ] */

/* Program segment header */
typedef struct {

	Elf32_Word		p_type;					/* Segment type */
	Elf32_Off		p_offset;				/* Segment file offset */
	Elf32_Addr		p_vaddr;				/* Segment virtual address */
 	Elf32_Addr		p_paddr;				/* Segment physical address */

	Elf32_Word		p_filesz;				/* Segment size in file */
	Elf32_Word		p_memsz;				/* Segment size in memory */
	// could be larger than p_filesz to indicate than more memory is reserved for uninitialized data (BSS)

	Elf32_Word    p_flags;                /* Segment flags */
	// memory authorization flag: 'PF_R' (read) | 'PF_W' (write) | 'PF_X' (execute)
 	Elf32_Word		p_align;			/* Segment alignment */

}	Elf32_Phdr;

/* Legal values for p_type */
# define PT_NULL	0 // Program header table entry unused
# define PT_LOAD	1 // Loadable program segment
# define PT_DYNAMIC	2 // dynamic links and shared library segment
# define PT_INTERP	3 // path to dynamic interpreter
/* [ ... ] */

#endif /* HAVE_ELF_H */

/* this is the word datatype returned by the syscall ptrace for PEEK */
#define PTRACE_WORD int32_t

// PAGE_SIZE	- the size of a memory page
// LO_USER		- the lowest address accessible from user space  (% PAGE_SIZE)
// HI_USER		- the highest address accessible from user space  (% PAGE_SIZE)

#if defined (__linux__)
	#define PAGE_SIZE	4096U
	#define LO_USER	4096U
	#define HI_USER	0xc0000000U

#elif defined (__FreeBSD__)
	#define PAGE_SIZE	4096U
	#define LO_USER	4096U
	#define HI_USER	0xbfc00000U

#else
	#error "ERROR: unknow operating system"
#endif

#define PAGE_MASK (~(PAGE_SIZE - 1))

/* ============================= BODY ============================= */

/* -----------------------   utils (libC)   ---------------------- */

static int	tolower(int c) { return (('A' <= c && c <= 'Z') ? (c + 32) : c); }

static char	*basename(char *pathname) {
	char *ptr = strrchr(pathname, '/');
	return ptr ? ptr + 1 : pathname;
}

// Reads a given number of bytes from the text segment.
// num_bytes must be a multiple of the word size
static int	read_text_segment(pid_t pid, unsigned addr, char *buf, size_t num_bytes) {

	/* determine number of words required to read num_bytes */
	int	num_words = num_bytes / sizeof(PTRACE_WORD);
	if ((num_bytes % sizeof(PTRACE_WORD)) != 0)
		num_words++;

	for (int i = 0; i < num_words; i++) {

		*((/* cast */(PTRACE_WORD *)buf) + i) = ptrace(PTRACE_PEEKTEXT, pid, addr + i * sizeof(PTRACE_WORD), 0);

		/* an error has occurred */
		if (errno != 0) {
			char	msg[1024];
			snprintf(msg, sizeof(msg), "ptrace(PTRACE_PEEKTEXT, pid, 0x%08x, 0)", (unsigned)(addr + i * sizeof(PTRACE_WORD)));
			perror(msg);
			return 0;
		}
	}
	return 1;
}

/* ------------------------   initiation   ----------------------- */

bool	ui_arg(int ac, char *av[], char **filename, unsigned *addr) {

	if (ac == 2) {
		*filename = av[1];
		return true;
	}
	else if (ac == 4) {

		*filename = av[3];
		if (!strcmp(av[1], "-a")) {

			if (strlen(av[2]) > 1 && (av[2][0] == '0') && (tolower(av[2][1]) == 'x'))
				*addr = strtol(av[2], NULL, 16);
			else
				*addr = strtol(av[2], NULL, 10);
			if (errno == ERANGE)
				return false;
		}
		return true;
	}
	return false;
}

void	child_proc(char *filename) {

	char	buff_error[BUFF_SIZE];

	/* it attaches the current process (the process executing this code) to a debugger */
	if (!ptrace(PTRACE_TRACEME, 0, 0, 0)) {
		if (-1 == execl(filename, filename, NULL)) {
			snprintf(buff_error, sizeof(buff_error), "couldn't exec `%s`", filename);
			perror(buff_error);
		}
	}
	else
		perror("ptrace(PTRACE_TRACEME, ...)");
	exit (0);
}

int	parent_proc(char *filename, unsigned addr, size_t file_size, pid_t pid) {

	int ret_val = 1;
	if (waitpid(pid, &status, WUNTRACED) == pid) {

		if (!WIFEXITED(status)) {
		/* SIGTRAP is delivered to child after execve */
		if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {

	/* ==============   to do   ============== */
            if (addr == 0)
               addr = find_elf_header(pid);
            if (addr != 0) {
               snprintf(out_filename, sizeof(out_filename), "%s.out",
                        basename(filename));

               if (save_to_file(out_filename, pid, addr, file_size)) {
                  chmod(out_filename, 00755);
                  fprintf(stdout, "created file `%s'\n", out_filename);
                  ret_val = EXIT_SUCCESS;
               }
            }
            else {
               fprintf(stderr, "couldn't find elf header in memory\n");
            }
         }
         else {
            fprintf(stderr, "didn't receive SIGTRAP after execve\n");
         }
	/* ======================================= */

		/* kill child as we are finished */
		ptrace(PTRACE_KILL, pid, 0, 0);
		}
	}
	else
		perror("waitpid");

	return ret_val;
}

int	main(int ac, char *av[]) {

	pid_t		pid = -1;
	char		buff_error[BUFF_SIZE];
	char		*filename = NULL;
	unsigned	addr = 0;
	struct stat	stat_buf;

	if (ui_arg(ac, av, &filename, &addr)) {
		fprintf(stderr, "Usage: %s [-a addr] <file>\n" \
			"where addr is the memory address of the ELF header\n", av[0]);
		return 1;
	}
	bzero(stat_buf, sizeof(stat_buf));
	if (stat(filename, &stat_buf)) {

		snprintf(buff_error, sizeof(buff_error), "couldn't stat file `%s`", filename);
		perror(buff_error);
		return 1;
	}
	if (-1 == (pid = fork())) {
		perror("fork()");
		return 1;
	}
	if (!pid)
		child_proc(filename);
	return parent_proc(filename, addr, stat_buf.st_size, pid);
}
