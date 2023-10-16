// {binary-executable-copy}.c
//
// Author: Noah BEAUFILS
// Date: 14-oct-2023
// From: [Copyright (C) 2002, 2003 Dion Mendel.]
// Functs: 12

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

#define NUM_ELF_HEADERS 10
#define PAGE_MASK (~(PAGE_SIZE - 1))

// usefull macros functions
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#define LO_PAGE_ADDR(phdr) ((phdr)->p_offset & PAGE_MASK)
#define HI_PAGE_ADDR(phdr) (((phdr)->p_offset + ((phdr)->p_filesz) + PAGE_SIZE - 1) & PAGE_MASK)

#define INTERSECTS(off1, size1, off2, size2) ( ((off1) < (off2)) ? ((off2) < (off1) + (size1)) : ((off1) < ((off2) + (size2))) )

/* ============================== BODY ============================= */

/* ------------------------   utils (libC)   ----------------------- */

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

/* ------------------------   functions   ----------------------- */

// Prints warning message for the bytes in the file that couldn't be recovered.
// Uses 0/0 for offset/size to signal end of all lost data.
static void	warn_lost_data (Elf32_Ehdr *ehdr, Elf32_Phdr *phdr, unsigned int offset, unsigned int size) {

	static unsigned int	last_offset;	/* for recording last offset */
	static unsigned int	last_size;		/* and size - initialised to zero */

	if ((offset && size) && last_offset + last_size == offset) {
		last_size += size;
		return ;
	}

	if (last_offset != 0 && last_size != 0) {
		fprintf(stderr, "could not recover data - %d bytes at file offset %d\n", last_size, last_offset);

		for (int i = 0; i < ehdr->e_phnum; i++) {
			if (phdr[i].p_type != PT_NULL) {
				if (INTERSECTS(last_offset, last_size, phdr[i].p_offset, phdr[i].p_filesz))
					fprintf(stderr, " ! data from phdr[%d] was not recovered\n", i);
			}
		}

		if ((ehdr->e_shnum != 0) && INTERSECTS(last_offset, last_size, \
			ehdr->e_shoff, ehdr->e_shnum * ehdr->e_shentsize))
			fprintf(stderr, " ! section header table was not recovered\n");
	}

	/* record this offset and size */
	last_offset = offset;
	last_size = size;
}

// map memory pages to position in file
static unsigned	*map_memory_pages(Elf32_Ehdr *ehdr, Elf32_Phdr *phdr, size_t file_size) {

	Elf32_Phdr	*this_phdr = NULL;
	int			num_pages = (file_size + PAGE_SIZE - 1) / PAGE_SIZE;
	unsigned	*pages = calloc(num_pages, sizeof(unsigned));
	if (!pages)
		return NULL;

	for (int i = 0; i < num_pages; i++) {
		for (int p = 0; p < ehdr->e_phnum; p++) {

			this_phdr = &phdr[p];
			if (this_phdr->p_type == PT_LOAD) {
				// check if this memory page match with this programm segment
				if (LO_PAGE_ADDR(this_phdr) <= (i * PAGE_SIZE) && ((i + 1) * PAGE_SIZE) <= HI_PAGE_ADDR(this_phdr)) {

					/* check for lost data in the last page of the segment */
					unsigned	end_segment_address = this_phdr->p_offset + this_phdr->p_filesz;
					bool last_page = end_segment_address < ((i + 1) * PAGE_SIZE);

					if (last_page && (this_phdr->p_memsz > this_phdr->p_filesz))
						warn_lost_data(ehdr, phdr, end_segment_address, ((i + 1) * PAGE_SIZE) - end_segment_address);
					// calculate memory address of the page
					pages[i] = phdr[p].p_vaddr - phdr[p].p_offset + (i * PAGE_SIZE);
					break;
				}
			}
		}
		/* warn about lost data if no memory page maps to file */
		if (!pages[i])
			warn_lost_data(ehdr, phdr, i * PAGE_SIZE, PAGE_SIZE);
	}
	/* signal that an attempt to recover all pages has been made */
	warn_lost_data(ehdr, phdr, 0, 0);
	return pages;
}

// Writes the memory pages to the given filename
static bool	create_file(char *filename, pid_t pid, Elf32_Ehdr *ehdr, Elf32_Phdr *phdr, size_t file_size) {

	bool		ret = false;
	FILE		*fptr = NULL;
	char		page[PAGE_SIZE];
	int			num_pages = (file_size + PAGE_SIZE - 1) / PAGE_SIZE;
	unsigned	*pages = map_memory_pages(ehdr, phdr, file_size);

	if (!pages) {
		perror("malloc");
		return false;
	}
	/* write memory pages to file */
	if ((fptr = fopen(filename, "wb"))) { // open a file in binary mode for writting
		for (int i = 0; i < num_pages; i++) {
			if (pages[i]) {
				if (!read_text_segment(pid, pages[i], page, PAGE_SIZE)) {
					fclose(fptr);
					free(pages);
					return false;
				}
			}
			else
				memset(page, '\0', PAGE_SIZE);
			fwrite(page, 1, MIN(file_size, PAGE_SIZE), fptr);
			file_size -= PAGE_SIZE;
		}
		fclose(fptr);
		ret = true;
	}
	else
		perror(filename);
	free(pages);
	return ret;
}

static bool	save_to_file(char *filename, pid_t pid, unsigned int addr, size_t file_size) {

	bool			ret = false;
	char		page[PAGE_SIZE] = { 0 };
	Elf32_Ehdr	*ehdr; /* file header */
	Elf32_Phdr	*phdr; /* segment header */

	if (read_text_segment(pid, addr, page, PAGE_SIZE)) {
		/* ensure 32bit elf binary */
		ehdr = (Elf32_Ehdr *)page;
		if (page[EI_CLASS] == ELFCLASS32 && ehdr->e_type == ET_EXEC) {

			/* ensure program header table is in same page as elf header */
			if ((ehdr->e_phoff + ehdr->e_phnum * ehdr->e_phentsize) < PAGE_SIZE) {
				phdr = (Elf32_Phdr *) (page + ehdr->e_phoff);
				ret = create_file(filename, pid, ehdr, phdr, file_size);
			}
			else
				fprintf(stderr, "program header table could not be found\n");
		}
		else
			fprintf(stderr, "no 32bit elf executable, found at addr 0x%08x\n", addr);
	}
	return ret;
}

// Searches memory for an elf header
static unsigned	find_elf_header(pid_t pid) {

	Elf32_Ehdr	hdr;
	PTRACE_WORD	word = 0;
	int			num_possible = 0;
	char		*elf_hdr = "\177ELF";
	unsigned	possible[NUM_ELF_HEADERS] = { 0 };

	/* search each page to see if elf header is found */
	for (unsigned addr = LO_USER; addr < HI_USER; addr += PAGE_SIZE) {
		bool	found_elf_header = false;

		word = ptrace(PTRACE_PEEKTEXT, pid, addr, 0);
		if ((errno == 0) && (word == *((PTRACE_WORD *)elf_hdr))) {
			if (read_text_segment(pid, addr, (char *)&hdr, sizeof(hdr))) {
				if (hdr.e_type == ET_EXEC)
					found_elf_header = true;
				else if (hdr.e_type == ET_DYN)
					fprintf(stderr, "discarding shared library at virtual memory address 0x%08x\n", addr);
			}
		}
		if (found_elf_header) {
			if (num_possible == NUM_ELF_HEADERS) {
				fprintf(stderr, "too many possible elf headers found (> %d)\n", NUM_ELF_HEADERS);
				return 0;
			}
			possible[num_possible] = addr;
			num_possible++;
		}
	}

	if (!num_possible)
		return 0; /* no elf header found */
	else if (num_possible == 1) {
		/* a single elf header was found */
		fprintf(stdout, "using elf header at virtual memory address 0x%08x\n", possible[0]);
		return possible[0];
	}
	else {
		/* need to resolve conflicts - let user decide */
		fprintf(stderr, "multiple elf headers found:\n");
		for (int i = 0; i < num_possible; i++)
			printf("  0x%08x\n", possible[i]);
		return 0;
	}
}

/* ------------------------   initiation   ----------------------- */

static bool	ui_arg(int ac, char *av[], char **filename, unsigned *addr) {

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

	char	buff_error[BUFF_SIZE] = { 0 };

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

	int 	ret_val = 1, status = 0;
	char	out_filename[BUFF_SIZE] = { 0 };

	if (waitpid(pid, &status, WUNTRACED) == pid) {

		if (!WIFEXITED(status)) {
		/* SIGTRAP is delivered to child after execve */
		if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {

			if (!addr)
				addr = find_elf_header(pid); // to do
			if (addr) {
				snprintf(out_filename, sizeof(out_filename), "%s.out", basename(filename));

				if (save_to_file(out_filename, pid, addr, file_size)) {
					chmod(out_filename, 00755);
					ret_val = 0;
				}
			}
			else
				fprintf(stderr, "couldn't find elf header in memory\n");
		}
		else
			fprintf(stderr, "didn't receive SIGTRAP after execve\n");

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

	if (!ui_arg(ac, av, &filename, &addr)) {
		fprintf(stderr, "Usage: %s [-a addr] <file>\n" \
			"where addr is the memory address of the ELF header\n", av[0]);
		return 1;
	}
	bzero(&stat_buf, sizeof(stat_buf));
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
