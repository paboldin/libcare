#ifndef __KPATCH_OBJECT_FILE__
#define __KPATCH_OBJECT_FILE__

#include <elf.h>

typedef struct kpatch_process kpatch_process_t;

typedef struct kpatch_object_file kpatch_object_file_t;
struct kpatch_object_file {
	struct list_head list;
	kpatch_process_t *proc;

	/**
	 * This is a pointer to storage's kpfile, readonly.
	 */
	const struct kp_file *skpfile;

	/**
	 * This is filled with kpatch information if is_patch = 1
	 * and used as a storage for copy of a patch from storage.
	 */
	struct kp_file kpfile;

	/* Pointer to jump table for DSO relocations */
	struct kpatch_jmp_table *jmp_table;

	/* Address of the patch in target's process address space */
	unsigned long kpta;

	/* Device the object resides on */
	dev_t dev;
	ino_t inode;

	/* Object name (as seen in /proc/<pid>/maps) */
	char *name;

	/* List of object's VM areas */
	struct list_head vma;

	/* Object's Build-ID */
	char buildid[41];

	/* Patch information */
	struct kpatch_info *info;
	size_t ninfo;

	/* Address of the first allocated virtual memory area */
	unsigned long vma_start;

	/*
	 * Load offset. Add this values to symbol addresses to get
	 * correct addresses in the loaded binary. Zero for EXEC,
	 * equals to `vma_start` for DYN (libs and PIEs)
	 */
	unsigned long load_offset;

	/* ELF header for the object file */
	Elf64_Ehdr ehdr;

	/* Program header */
	Elf64_Phdr *phdr;

	/* Dynamic symbols exported by the object if it is a library */
	Elf64_Sym *dynsyms;
	size_t ndynsyms;

	char **dynsymnames;

	/* Pointer to the previous hole in the patient's mapping */
	struct vm_hole *previous_hole;

	/* Pointer to the applied patch, if any */
	kpatch_object_file_t *applied_patch;

	/* Do we have patch for the object? */
	unsigned int has_patch:1;

	/* Is that a patch for some object? */
	unsigned int is_patch:1;

	/* Is it a shared library? */
	unsigned int is_shared_lib:1;

	/* Is it an ELF or a mmap'ed regular file? */
	unsigned int is_elf:1;
};


const char *
kpatch_object_get_buildid(kpatch_object_file_t *o);

void
kpatch_object_dump(kpatch_object_file_t *o);


/*
 * Set ELF header (and program headers if they fit)
 * from the already read `buf` of size `bufsize`.
 */
int
kpatch_object_set_ehdr(kpatch_object_file_t *o,
		       const unsigned char *buf,
		       size_t bufsize);

int kpatch_object_is_shared_lib(kpatch_object_file_t *o);
int kpatch_object_parse_program_header(kpatch_object_file_t *o);
int kpatch_object_load_kpatch_info(kpatch_object_file_t *o);

int kpatch_object_patch_resolve(kpatch_object_file_t *o);
int kpatch_object_patch_relocate(kpatch_object_file_t *o);

struct kpatch_jmp_table *kpatch_new_jmp_table(int entries);
int kpatch_object_count_undefined(kpatch_object_file_t *o);

int kpatch_object_resolve_dynamic(kpatch_object_file_t *o,
				  const char *sname,
				  unsigned long *addr);

unsigned long vaddr2addr(kpatch_object_file_t *o, unsigned long vaddr);

struct kpatch_jmp_table_entry {
	unsigned long jmp;
	unsigned long addr;
};

struct kpatch_jmp_table {
	unsigned int size;
	unsigned int cur_entry;
	unsigned int max_entry;

	struct kpatch_jmp_table_entry entries[0];
};

#endif
