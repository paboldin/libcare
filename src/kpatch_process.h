#ifndef __KPATCH_PROCESS__
#define __KPATCH_PROCESS__

#include <libunwind.h>

#include "kpatch_common.h"
#include "kpatch_coro.h"
#include "kpatch_file.h"
#include "list.h"
#include "kpatch_layout.h"

struct kpatch_process;
typedef struct kpatch_process kpatch_process_t;

struct kpatch_process {
	/* Pid of target process */
	int pid;

	/* memory fd of /proc/<pid>/mem */
	int memfd;

	/* /proc/<pid>/maps FD, also works as lock */
	int fdmaps;

	/* Process name */
	char comm[16];

	/* List ptrace contexts (one per each thread) */
	struct {
		struct list_head pctxs;
		unw_addr_space_t unwd;
	} ptrace;

	/* List of coroutines + ops to manipulate */
	struct {
		struct list_head coros;
		unw_addr_space_t unwd;
	} coro;

	/* Process memory layout */
	kpatch_process_layout_t layout;

	/*
	 * Is client have been stopped right before the `execve`
	 * and awaiting our response via this fd?
	 */
	int send_fd;

	/* Just started process? */
	unsigned int is_just_started:1;

	/* Is it an ld-linux trampoline? */
	unsigned int is_ld_linux:1;
};

int
kpatch_process_attach(kpatch_process_t *proc);

enum {
	MEM_READ,
	MEM_WRITE,
};
int
kpatch_process_mem_open(kpatch_process_t *proc, int mode);
int
kpatch_process_load_libraries(kpatch_process_t *proc);
int
kpatch_process_kick_send_fd(kpatch_process_t *proc);

int
kpatch_process_execute_until_stop(kpatch_process_t *proc);

void
kpatch_process_print_short(kpatch_process_t *proc);

int
kpatch_process_init(kpatch_process_t *proc,
		    int pid,
		    int is_just_started,
		    int send_fd);
void
kpatch_process_free(kpatch_process_t *proc);


#endif /* ifndef __KPATCH_PROCESS__ */
