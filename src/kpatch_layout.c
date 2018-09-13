#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <regex.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

#include <gelf.h>
#include <libunwind.h>
#include <libunwind-ptrace.h>

#include <sys/socket.h>

#include "kpatch_process.h"
#include "kpatch_file.h"
#include "kpatch_common.h"
#include "kpatch_elf.h"
#include "kpatch_ptrace.h"
#include "list.h"
#include "kpatch_log.h"

static int
vm_area_same(struct vm_area *a, struct vm_area *b)
{
	return ((a->start == b->start) &&
		(a->end == b->end) &&
		(a->prot == b->prot));
}

static int
object_add_vm_area(struct object_file *o,
		   struct vm_area *vma,
		   struct vm_hole *hole)
{
	struct obj_vm_area *ovma;

	if (o->previous_hole == NULL)
		o->previous_hole = hole;
	list_for_each_entry(ovma, &o->vma, list) {
		if (vm_area_same(vma, &ovma->inmem))
			return 0;
	}
	ovma = malloc(sizeof(*ovma));
	if (!ovma)
		return -1;
	memset(ovma, 0, sizeof(*ovma));
	ovma->inmem = *vma;
	list_add(&ovma->list, &o->vma);
	return 0;
}

static struct object_file *
process_new_object(kpatch_process_t *proc,
		   dev_t dev, int inode,
		   const char *name, struct vm_area *vma,
		   struct vm_hole *hole)
{
	struct object_file *o;

	kpdebug("Creating object file '%s' for %lx:%d...", name, dev, inode);

	o = malloc(sizeof(*o));
	if (!o) {
		kpdebug("FAIL\n");
		return NULL;
	}
	list_init(&o->list);
	list_init(&o->vma);
	o->proc = proc;
	o->skpfile = NULL;
	o->dev = dev;
	o->inode = inode;
	o->is_patch = 0;
	o->jmp_table = NULL;

	o->previous_hole = hole;
	if (object_add_vm_area(o, vma, hole) < 0) {
		kplogerror("can't add vm_area for %s\n", name);
		free(o);
		return NULL;
	}

	o->name = strdup(name);
	o->buildid[0] = '\0';
	o->kpta = 0UL;
	o->info = NULL;
	o->ninfo = 0;
	o->applied_patch = NULL;
	o->vma_start = ~(unsigned long)0;
	o->load_offset = ~(unsigned long)0;
	memset(&o->ehdr, 0, sizeof(o->ehdr));
	o->phdr = NULL;
	o->is_elf = 0;
	o->dynsyms = NULL;
	o->ndynsyms = 0;
	o->dynsymnames = NULL;
	init_kp_file(&o->kpfile);
	list_add(&o->list, &proc->layout.objs);
	proc->layout.num_objs++;
	kpdebug("OK\n");
	return o;
}

#define OBJECT_UNKNOWN	0
#define OBJECT_ELF	1
#define OBJECT_KPATCH	2

#define	ELFMAG		"\177ELF"
#define SELFMAG		4

static int
process_get_object_type(kpatch_process_t *proc,
			struct vm_area *vma,
			char *name,
			unsigned char *buf,
			size_t bufsize)
{
	int ret, type = OBJECT_UNKNOWN;

	if (bufsize < sizeof(struct kpatch_file)) {
		return -1;
	}

	if (!strcmp(name, "[anonymous]") &&
	    vma->prot == (PROT_READ | PROT_WRITE | PROT_EXEC) &&
	    (vma->end - vma->start) >= sizeof(struct kpatch_file))
		type = OBJECT_KPATCH;

	ret = kpatch_process_mem_read(proc,
				      vma->start,
				      buf,
				      bufsize);
	if (ret <= SELFMAG)
		return -1;

	if (type == OBJECT_KPATCH) {
		struct kpatch_file *pkpfile = (struct kpatch_file *)buf;

		if (!strcmp(pkpfile->magic, KPATCH_FILE_MAGIC1)) {
			sprintf(name, "[kpatch-%s]", pkpfile->uname);
			return type;
		}
	}

	if (!memcmp(buf, ELFMAG, SELFMAG)) {
		type = OBJECT_ELF;
	} else {
		type = OBJECT_UNKNOWN;
	}

	return type;
}

/**
 * Returns: 0 if everything is ok, -1 on error.
 */
static int
process_add_object_vma(kpatch_process_t *proc,
		       dev_t dev, int inode,
		       char *name, struct vm_area *vma,
		       struct vm_hole *hole)
{
	int object_type, rv;
	unsigned char header_buf[1024];
	struct object_file *o;

	object_type = process_get_object_type(proc,
					      vma,
					      name,
					      header_buf,
					      sizeof(header_buf));

	if (object_type != OBJECT_KPATCH) {
		/* Is not a kpatch, look if this is a vm_area of an already
		 * enlisted object.
		 */
		for_each_object_reverse(o, proc) {
			if ((dev && inode && o->dev == dev &&
			     o->inode == inode) ||
			    (dev == 0 && !strcmp(o->name, name))) {
				return object_add_vm_area(o, vma, hole);
			}
		}
	}

	o = process_new_object(proc, dev, inode, name, vma, hole);
	if (o == NULL)
		return -1;

	if (object_type == OBJECT_KPATCH) {
		struct kpatch_file *patch;

		patch = malloc(sizeof(header_buf));
		if (patch == NULL)
			return -1;

		memcpy(patch, header_buf, sizeof(header_buf));
		o->kpfile.patch = patch;
		o->kpfile.size = vma->end - vma->start;

		o->is_patch = 1;
	} else if (object_type == OBJECT_ELF) {
		o->is_elf = 1;
		rv = kpatch_elf_object_set_ehdr(o,
						header_buf,
						sizeof(header_buf));
		if (rv < 0)
			kperr("unable to kpatch_elf_object_set_ehdr\n");
	}

	return 0;
}

static int
object_map_elf_segments(struct object_file *o)
{
	int ret;

	if (is_kernel_object_name(o->name))
		return 0;

	kpdebug("Populating object %x:%lu (%s)...", (unsigned int)o->dev,
		o->inode, o->name);

	if (!o->is_elf) {
		kpdebug("File is not an ELF, ignoring...\n");
		return 0;
	}

	kpdebug("Populating ondisk ELF segments for '%s'...", o->name);
	ret = kpatch_elf_object_is_shared_lib(o);
	if (ret < 0) {
		kperr("can't process ELF file\n");
		return -1;
	}
	o->is_shared_lib = ret;

	ret = kpatch_elf_parse_program_header(o);
	if (ret < 0)
		kperr("can't parse program header\n");
	else
		kpdebug("OK\n");

	return ret;
}

static void
object_destroy(struct object_file *o)
{
	struct obj_vm_area *ovma, *tmp;

	list_del(&o->list);
	list_for_each_entry_safe(ovma, tmp, &o->vma, list) {
		list_del(&ovma->list);
		free(ovma);
	}
	o->proc->layout.num_objs--;
	if (o->jmp_table)
		free(o->jmp_table);
	if (o->name)
		free(o->name);
	if (o->phdr)
		free(o->phdr);
	if (o->dynsyms)
		free(o->dynsyms);
	if (o->dynsymnames)
		free(o->dynsymnames);
	if (o->is_patch) {
		free(o->info);
	}
	if (o->applied_patch == NULL)
		free(o->kpfile.patch);
	free(o);
}

#define PROT_FMT "%c%c%c"
#define PROT_ARGS(p) \
	(p & PROT_READ) ? 'r' : '-', \
	(p & PROT_WRITE) ? 'w' : '-', \
	(p & PROT_EXEC) ? 'e' : '-'

void
kpatch_object_dump(struct object_file *o)
{
	struct obj_vm_area *ovma;
	char *patchinfo;

	if (log_level < LOG_INFO)
		return;

	if (o->applied_patch)
		patchinfo = o->applied_patch->name;
	else
		patchinfo = o->skpfile != NULL ? "yes" : "no";

	kpdebug("Object '%s' (%lx:%ld), patch: %s\n",
		o->name, o->dev, o->inode, patchinfo);
	kpdebug("VM areas:\n");
	list_for_each_entry(ovma, &o->vma, list)
		kpdebug("  inmem: %08lx-%08lx "PROT_FMT", ondisk: %08lx-%08lx "PROT_FMT"\n",
			ovma->inmem.start, ovma->inmem.end, PROT_ARGS(ovma->inmem.prot),
			ovma->ondisk.start, ovma->ondisk.end, PROT_ARGS(ovma->ondisk.prot));
}

static unsigned int
perms2prot(char *perms)
{
	unsigned int prot = 0;

	if (perms[0] == 'r')
		prot |= PROT_READ;
	if (perms[1] == 'w')
		prot |= PROT_WRITE;
	if (perms[2] == 'x')
		prot |= PROT_EXEC;
	/* Ignore 'p'/'s' flag, we don't need it */
	return prot;
}

static struct vm_hole *
process_add_vm_hole(kpatch_process_t *proc,
		    unsigned long hole_start,
		    unsigned long hole_end)
{
	struct vm_hole *hole;

	hole = malloc(sizeof(*hole));
	if (hole == NULL)
		return NULL;

	hole->start = hole_start;
	hole->end = hole_end;

	list_add(&hole->list, &proc->layout.vmaholes);

	return hole;
}

int
kpatch_process_associate_patches(kpatch_process_t *proc)
{
	struct object_file *o, *objpatch;
	size_t found = 0;

	for_each_object(objpatch, proc) {

		if (!objpatch->is_patch)
			continue;

		for_each_object(o, proc) {
			const char *bid;
			struct obj_vm_area *patchvma;

			bid = kpatch_get_buildid(o);
			if (o->applied_patch != NULL || bid == NULL ||
			    strcmp(bid, objpatch->kpfile.patch->uname))
				continue;

			o->applied_patch = objpatch;
			patchvma = list_first_entry(&objpatch->vma,
						    struct obj_vm_area,
						    list);
			o->kpta = patchvma->inmem.start;
			o->kpfile = objpatch->kpfile;

			found++;
			break;
		}
	}

	return found;
}

int
kpatch_process_parse_proc_maps(kpatch_process_t *proc)
{
	FILE *f;
	int ret, fd, is_libc_base_set = 0;
	unsigned long hole_start = 0;
	struct vm_hole *hole = NULL;

	/*
	 * 1. Create the list of all objects in the process
	 * 2. Check whether we have patch for any of them
	 * 3. If we have at least one patch, create files for all
	 *    of the object (we might have references to them
	 *    in the patch).
	 */
	fd = dup(proc->fdmaps);
	if (fd < 0) {
		kperr("unable to dup fd %d\n", proc->fdmaps);
		return -1;
	}

	lseek(fd, 0, SEEK_SET);
	f = fdopen(fd, "r");
	if (f == NULL) {
		kperr("unable to fdopen %d\n", fd);
		close(fd);
		return -1;
	}

	do {
		struct vm_area vma;
		char line[1024];
		unsigned long start, end, offset;
		unsigned int maj, min, inode;
		char perms[5], name_[256], *name = name_;
		int r;

		if (!fgets(line, sizeof(line), f))
			break;
		r = sscanf(line, "%lx-%lx %s %lx %x:%x %d %255s",
			   &start, &end, perms, &offset,
			   &maj, &min, &inode, name_);
		if (r != 8)
			strcpy(name, "[anonymous]");

		vma.start = start;
		vma.end = end;
		vma.offset = offset;
		vma.prot = perms2prot(perms);


		/* Hole must be at least 2 pages for guardians */
		if (start - hole_start > 2 * PAGE_SIZE) {
			hole = process_add_vm_hole(proc,
						   hole_start + PAGE_SIZE,
						   start - PAGE_SIZE);
			if (hole == NULL)
				goto error;
		}
		hole_start = end;

		name = name[0] == '/' ? basename(name) : name;

		ret = process_add_object_vma(proc, makedev(maj, min),
					     inode, name, &vma, hole);
		if (ret < 0)
			goto error;

		if (!is_libc_base_set &&
		    !strncmp(basename(name), "libc", 4) &&
		    vma.prot & PROT_EXEC) {
			proc->layout.libc_base = start;
			is_libc_base_set = 1;
		}

	} while (1);
	fclose(f);

	if (!is_libc_base_set) {
		kperr("Can't find libc_base required for manipulations: %d\n",
		      proc->pid);
		return -1;
	}

	kpinfo("Found %d object file(s).\n", proc->layout.num_objs);

	return 0;

error:
	fclose(f);
	return -1;
}

int
kpatch_process_map_object_files(kpatch_process_t *proc)
{
	struct object_file *o;
	int ret;

	ret = kpatch_process_parse_proc_maps(proc);
	if (ret < 0)
		return -1;

	for_each_object(o, proc) {
		ret = object_map_elf_segments(o);
		if (ret)
			return -1;
	}

	ret = kpatch_process_associate_patches(proc);
	if (ret >= 0) {
		kpinfo("Found %d applied patch(es).\n", ret);
	}

	return 0;
}

void
kpatch_process_destroy_object_files(kpatch_process_t *proc)
{
	struct object_file *o, *tmp;

	for_each_object_safe(o, tmp, proc)
		object_destroy(o);
}

static int
vm_hole_split(struct vm_hole *hole,
	      unsigned long alloc_start,
	      unsigned long alloc_end)
{
	alloc_start = ROUND_DOWN(alloc_start, PAGE_SIZE) - PAGE_SIZE;
	alloc_end = ROUND_UP(alloc_end, PAGE_SIZE) + PAGE_SIZE;

	if (alloc_start > hole->start) {
		struct vm_hole *left = NULL;

		left = malloc(sizeof(*hole));
		if (left == NULL)
			return -1;

		left->start = hole->start;
		left->end = alloc_start;

		list_add(&left->list, &hole->list);
	}

	/* Reuse hole pointer as the right hole since it is pointed to by
	 * the `previous_hole` of some `object_file`. */
	hole->start = alloc_end;
	hole->end = hole->end > alloc_end ? hole->end : alloc_end;

	return 0;
}

static inline struct vm_hole *
next_hole(struct vm_hole *hole, struct list_head *head)
{
	if (hole == NULL || hole->list.next == head)
		return NULL;

	return list_entry(hole->list.next, struct vm_hole, list);
}

static inline struct vm_hole *
prev_hole(struct vm_hole *hole, struct list_head *head)
{
	if (hole == NULL || hole->list.prev == head)
		return NULL;

	return list_entry(hole->list.prev, struct vm_hole, list);
}

static inline unsigned long
hole_size(struct vm_hole *hole)
{
	if (hole == NULL)
		return 0;
	return hole->end - hole->start;
}

static unsigned long
random_from_range(unsigned long min, unsigned long max)
{
	/* TODO this is not uniform nor safe */
	return min + random() % (max - min);
}

/*
 * Find region for a patch. Take object's `previous_hole` as a left candidate
 * and the next hole as a right candidate. Pace through them until there is
 * enough space in the hole for the patch.
 *
 * Since holes can be much larger than 2GiB take extra caution to allocate
 * patch region inside the (-2GiB, +2GiB) range from the original object.
 */
static unsigned long
object_find_patch_region(struct object_file *obj,
			 size_t memsize,
			 struct vm_hole **hole)
{
	struct list_head *head = &obj->proc->layout.vmaholes;
	struct vm_hole *left_hole = obj->previous_hole,
		       *right_hole = next_hole(left_hole, head);
	unsigned long max_distance = 0x80000000;
	struct obj_vm_area *sovma;

	unsigned long obj_start, obj_end;
	unsigned long region_start = 0, region_end = 0;

	kpdebug("Looking for patch region for '%s'...\n", obj->name);

	sovma = list_first_entry(&obj->vma, struct obj_vm_area, list);
	obj_start = sovma->inmem.start;
	sovma = list_entry(obj->vma.prev, struct obj_vm_area, list);
	obj_end = sovma->inmem.end;


	max_distance -= memsize;

	/* TODO carefully check for the holes laying between obj_start and
	 * obj_end, i.e. just after the executable segment of an executable
	 */
	while (left_hole != NULL && right_hole != NULL) {
		if (right_hole != NULL &&
		    right_hole->start - obj_start > max_distance)
			right_hole = NULL;
		else if (hole_size(right_hole) > memsize) {
			region_start = right_hole->start;
			region_end =
				(right_hole->end - obj_start) <= max_distance ?
				right_hole->end - memsize :
				obj_start + max_distance;
			*hole = right_hole;
			break;
		} else
			right_hole = next_hole(right_hole, head);

		if (left_hole != NULL &&
		    obj_end - left_hole->end > max_distance)
			left_hole = NULL;
		else if (hole_size(left_hole) > memsize) {
			region_start =
				(left_hole->start - obj_end) <= max_distance ?
				left_hole->start : obj_end > max_distance    ?
				obj_end - max_distance : 0;
			region_end = left_hole->end - memsize;
			*hole = left_hole;
			break;
		} else
			left_hole = prev_hole(left_hole, head);
	}

	if (region_start == region_end) {
		kperr("can't find suitable region for patch on '%s'\n",
		      obj->name);
		return -1UL;
	}

	region_start = random_from_range(region_start >> PAGE_SHIFT,
					 region_end >> PAGE_SHIFT);
	region_start <<= PAGE_SHIFT;
	kpdebug("Found patch region for '%s' at %lx\n", obj->name, region_start);

	return region_start;
}

int
kpatch_object_allocate_patch(struct object_file *o,
			     size_t sz)
{
	unsigned long addr;
	struct vm_hole *hole = NULL;


	addr = object_find_patch_region(o, sz, &hole);
	if (!addr)
		return -1;

	addr = kpatch_mmap_remote(proc2pctx(o->proc),
				  addr, sz,
				  PROT_READ | PROT_WRITE | PROT_EXEC,
				  MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (addr == 0) {
		kplogerror("remote alloc of 0x%lx bytes failed\n",
			   addr);
		return -1;
	}

	o->kpta = addr;

	kpinfo("allocated 0x%lx bytes at 0x%lx for '%s' patch\n",
	       sz, o->kpta, o->name);

	kpdebug("Marking this space as busy\n");
	return vm_hole_split(hole, addr, addr + sz);
}

struct object_file *
kpatch_process_get_obj_by_regex(kpatch_process_t *proc, const char *regex)
{
	struct object_file *o, *found = NULL;
	regex_t r;
	int rv;

	rv = regcomp(&r, regex, 0);
	if (rv != 0) {
		char errbuf[1024];

		regerror(rv, &r, errbuf, sizeof(errbuf));

		kperr("regcomp failed: %d, %s\n", rv, errbuf);

		return NULL;
	}

	for_each_object(o, proc)
		if (!regexec(&r, o->name, 0, NULL, 0)) {
			found = o;
			break;
		}

	regfree(&r);
	return found;
}
