#ifndef __KPATCH_OBJECT__
#define __KPATCH_OBJECT__

#include <elf.h>
#include "kpatch_object_file.h"

struct kpatch_process;
typedef struct kpatch_process kpatch_process_t;

struct vm_area {
	unsigned long start;
	unsigned long end;
	unsigned long offset;
	unsigned int prot;
};

struct vm_hole {
	unsigned long start;
	unsigned long end;
	struct list_head list;
};

struct obj_vm_area {
	struct vm_area inmem;
	struct vm_area inelf;
	struct vm_area ondisk;
	struct list_head list;
};

struct kpatch_process_layout {
	/* List of process objects, kpatch_object_file_t */
	struct list_head objs;
	int num_objs;

	/* List of free VMA areas */
	struct list_head vmaholes;

	/* libc's base address to use as a worksheet */
	unsigned long libc_base;
};
typedef struct kpatch_process_layout kpatch_process_layout_t;

int
kpatch_process_associate_patches(kpatch_process_t *proc);
int
kpatch_process_parse_proc_maps(kpatch_process_t *proc);
int
kpatch_process_map_object_files(kpatch_process_t *proc);
void
kpatch_process_destroy_object_files(kpatch_process_t *proc);
int
kpatch_object_patch_allocate(kpatch_object_file_t *obj, size_t sz);


kpatch_object_file_t *
kpatch_process_get_obj_by_regex(kpatch_process_t *proc, const char *regex);

#define for_each_object(obj, proc)			\
	list_for_each_entry(obj, &(proc)->layout.objs, list)

#define for_each_object_reverse(obj, proc)		\
	list_for_each_entry_reverse(obj, &(proc)->layout.objs, list)

#define for_each_object_safe(obj, tmp, proc)		\
	list_for_each_entry_safe(obj, tmp, &(proc)->layout.objs, list)


static inline void
kpatch_process_layout_init(kpatch_process_layout_t *layout)
{
	list_init(&layout->objs);
	list_init(&layout->vmaholes);
	layout->num_objs = 0;
}

static inline void
kpatch_process_layout_free(kpatch_process_layout_t *layout)
{
	struct vm_hole *hole, *tmp;

	list_for_each_entry_safe(hole, tmp, &layout->vmaholes, list) {
		list_del(&hole->list);
		free(hole);
	}
}


static inline int
is_kernel_object_name(char *name)
{
       if ((name[0] == '[') && (name[strlen(name) - 1] == ']'))
               return 1;
       if (strncmp(name, "anon_inode", 10) == 0)
               return 1;
       return 0;
}

#endif /* __KPATCH_OBJECT__ */
