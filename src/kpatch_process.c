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
#include "kpatch_object_file.h"
#include "kpatch_ptrace.h"
#include "list.h"
#include "kpatch_log.h"

/* TODO(pboldin): further split this into process/main process/objects */

/*
 * Locks process by opening /proc/<pid>/maps
 * This ensures that task_struct will not be
 * deleted in the kernel while we are working with
 * the process
 */
static int lock_process(int pid)
{
	int fd;
	char path[128];

	kpdebug("Locking PID %d...", pid);
	snprintf(path, sizeof(path), "/proc/%d/maps", pid);
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		kplogerror("cannot open '/proc/%d/maps'\n", pid);
		return -1;
	}
	kpdebug("OK\n");
	return fd;
}

static void unlock_process(int pid, int fdmaps)
{
	int errsv = errno;
	close(fdmaps);
	errno = errsv;
}

static void
process_detach(kpatch_process_t *proc)
{
	struct kpatch_ptrace_ctx *p, *ptmp;
	int status;
	pid_t pid;

	if (proc->memfd >= 0 && close(proc->memfd) < 0)
		kplogerror("can't close memfd");
	proc->memfd = -1;

	if (proc->ptrace.unwd)
		unw_destroy_addr_space(proc->ptrace.unwd);

	list_for_each_entry_safe(p, ptmp, &proc->ptrace.pctxs, list) {
		if (kpatch_ptrace_detach(p) == -ESRCH) {
			do {
				pid = waitpid(p->pid, &status, __WALL);
			} while (pid > 0 && !WIFEXITED(status));
		}
		kpatch_ptrace_ctx_destroy(p);
	}
	kpinfo("Finished ptrace detaching.");
}

static int
process_list_threads(kpatch_process_t *proc,
		     int **ppids,
		     size_t *npids,
		     size_t *alloc)
{
	DIR *dir;
	struct dirent *de;
	char path[128];
	int *pids = *ppids;

	snprintf(path, sizeof(path), "/proc/%d/task", proc->pid);
	dir = opendir(path);
	if (!dir) {
		kplogerror("can't open '%s' directory\n", path);
		return -1;
	}

	*npids = 0;
	while ((de = readdir(dir))) {
		int *t;
		if (de->d_name[0] == '.')
			continue;

		if (*npids >= *alloc) {
			*alloc = *alloc ? *alloc * 2 : 1;

			t = realloc(pids, *alloc * sizeof(*pids));
			if (t == NULL) {
				kplogerror("Failed to (re)allocate memory for pids\n");
				closedir(dir);
				goto dealloc;
			}

			pids = t;
		}

		pids[*npids] = atoi(de->d_name);
		(*npids)++;
	}
	closedir(dir);

	*ppids = pids;

	return *npids;

dealloc:
	free(pids);
	*alloc = *npids = 0;
	return -1;
}

static const int max_attach_attempts = 3;

static int
process_has_thread_pid(kpatch_process_t *proc, int pid)
{
	struct kpatch_ptrace_ctx *pctx;

	list_for_each_entry(pctx, &proc->ptrace.pctxs, list)
		if (pctx->pid == pid)
			return 1;

	return 0;
}

int
kpatch_process_mem_open(kpatch_process_t *proc, int mode)
{
	char path[sizeof("/proc/0123456789/mem")];

	if (proc->memfd >= 0) {
		close(proc->memfd);
	}

	snprintf(path, sizeof(path), "/proc/%d/mem", proc->pid);
	proc->memfd = open(path, mode == MEM_WRITE ? O_RDWR : O_RDONLY);
	if (proc->memfd < 0) {
		kplogerror("can't open /proc/%d/mem", proc->pid);
		return -1;
	}

	return 0;
}

int
kpatch_process_attach(kpatch_process_t *proc)
{
	int *pids = NULL, ret;
	size_t i, npids = 0, alloc = 0, prevnpids = 0, nattempts;

	if (kpatch_process_mem_open(proc, MEM_WRITE) < 0)
		return -1;

	for (nattempts = 0; nattempts < max_attach_attempts; nattempts++) {
		ret = process_list_threads(proc, &pids, &npids, &alloc);
		if (ret == -1)
			goto detach;

		if (nattempts == 0) {
			kpdebug("Found %lu thread(s), attaching...\n", npids);
		} else {
			/*
			 * FIXME(pboldin): This is wrong, amount of threads can
			 * be the same because some new spawned and some old
			 * died
			 */
			if (prevnpids == npids)
				break;

			kpdebug("Found %lu new thread(s), attaching...\n",
				prevnpids - npids);
		}

		if (proc->is_just_started && npids > 1 && proc->send_fd == -1) {
			kperr("ERROR: is_just_started && nr > 1 && proc->send_fd == -1\n");
			goto dealloc;
		}

		for (i = prevnpids; i < npids; i++) {
			int pid = pids[i];

			if (process_has_thread_pid(proc, pid)) {
				kpdebug("already have pid %d\n", pid);
				continue;
			}

			ret = kpatch_ptrace_attach_thread(proc, pid);
			if (ret < 0)
				goto detach;
		}

		prevnpids = npids;
	}

	if (nattempts == max_attach_attempts) {
		kperr("unable to catch up with process, bailing\n");
		goto detach;
	}

	kpinfo("attached to %lu thread(s): %d", npids, pids[0]);
	for (i = 1; i < npids; i++)
		kpinfo(", %d", pids[i]);
	kpinfo("\n");

	free(pids);

	if (proc->ptrace.unwd == NULL) {
		proc->ptrace.unwd = unw_create_addr_space(&_UPT_accessors,
							  __LITTLE_ENDIAN);
		if (!proc->ptrace.unwd) {
			kperr("Can't create libunwind address space\n");
			goto detach;
		}
	}

	return 0;

detach:
	process_detach(proc);
dealloc:
	free(pids);
	return -1;
}

static void
process_print_cmdline(kpatch_process_t *proc)
{
	char buf[1024];
	int fd;
	ssize_t i, rv;

	sprintf(buf, "/proc/%d/cmdline", proc->pid);
	fd = open(buf, O_RDONLY);
	if (fd == -1) {
		kplogerror("open\n");
		return;
	}

	while (1) {
		rv = read(fd, buf, sizeof(buf));

		if (rv == -1 && errno == EINTR)
			continue;

		if (rv == -1) {
			kplogerror("read\n");
			goto err_close;
		}

		if (rv == 0)
			break;

		for (i = 0; i < rv; i++) {
			if (buf[i] != '\n' && isprint(buf[i]))
				putchar(buf[i]);
			else
				printf("\\x%02x", (unsigned char)buf[i]);
		}
	}


err_close:
	close(fd);
}

static int
process_get_comm_ld_linux(kpatch_process_t *proc)
{
	char buf[1024], *p;
	int fd;
	ssize_t i, rv;

	kpdebug("process_get_comm_ld_linux");
	sprintf(buf, "/proc/%d/cmdline", proc->pid);
	fd = open(buf, O_RDONLY);
	if (fd == -1) {
		kplogerror("open\n");
		return -1;
	}

	rv = read(fd, buf, sizeof(buf));
	if (rv == -1) {
		kplogerror("read\n");
		goto err_close;
	}

	for (p = buf; (p - buf) < rv; p++)
		if (*p == '\0')
			break;

	if (p == buf) {
		kperr("can't find buffer\n");
		goto err_close;
	}

	p++;

	for (i = 0; &p[i] < buf; i++)
		if (p[i] == '\0')
			break;

	if (&p[i] == buf) {
		kperr("can't find buffer\n");
		goto err_close;
	}

	close(fd);

	proc->comm[sizeof(proc->comm) - 1] = '\0';
	strncpy(proc->comm, basename(p), sizeof(proc->comm) - 1);

	return 0;

err_close:
	close(fd);
	return -1;
}

static int
process_get_comm(kpatch_process_t *proc)
{
	char path[128];
	char realpath[PATH_MAX];
	char *bn, *c;
	ssize_t ret;

	kpdebug("process_get_comm %d...", proc->pid);
	snprintf(path, sizeof(path), "/proc/%d/exe", proc->pid);
	ret = readlink(path, realpath, sizeof(realpath));
	if (ret < 0)
		return -1;
	realpath[ret] = '\0';
	bn = basename(realpath);
	strncpy(path, bn, sizeof(path));
	if ((c = strstr(path, " (deleted)")))
		*c = '\0';
	strncpy(proc->comm, path, sizeof(proc->comm));

	if (!strncmp(proc->comm, "ld", 2)) {
		proc->is_ld_linux = 1;
		return process_get_comm_ld_linux(proc);
	}
	kpdebug("OK\n");

	return 0;
}

static int
kpatch_process_kickstart_execve_wrapper(kpatch_process_t *proc)
{
	int ret;

	ret = kpatch_ptrace_kickstart_execve_wrapper(proc);
	if (ret < 0)
		return -1;

	/* TODO(pboldin) race here */
	unlock_process(proc->pid, proc->fdmaps);

	ret = lock_process(proc->pid);
	if (ret < 0)
		return -1;
	proc->fdmaps = ret;

	ret = process_get_comm(proc);
	if (ret < 0)
		return -1;

	printf("kpatch_ctl real cmdline=\"");
	process_print_cmdline(proc);
	printf("\"\n");

	return 0;
}

int
kpatch_process_kick_send_fd(kpatch_process_t *proc)
{
	int dummy = 0;

	if (proc->send_fd == -1 || proc->is_just_started)
		return 0;

	return send(proc->send_fd, &dummy, sizeof(dummy), 0);
}

int
kpatch_process_load_libraries(kpatch_process_t *proc)
{
	unsigned long entry_point;
	int ret;

	if (!proc->is_just_started)
		return 0;

	ret = kpatch_process_attach(proc);
	if (ret < 0) {
		kperr("unable to attach to just started process\n");
		return -1;
	}

	if (proc->send_fd != -1) {
		ret = kpatch_process_kickstart_execve_wrapper(proc);
		if (ret < 0) {
			kperr("Unable to kickstart execve\n");
			return -1;
		}
	}

	if (proc->is_ld_linux)
		ret = kpatch_ptrace_handle_ld_linux(proc, &entry_point);
	else
		ret = kpatch_ptrace_get_entry_point(proc2pctx(proc),
						    &entry_point);

	if (ret < 0) {
		kperr("unable to find entry point\n");
		return ret;
	}

	/* Note: kpatch_process_kickstart_execve_wrapper might change
	 * proc->pctxs */
	proc2pctx(proc)->execute_until = entry_point;
	ret = kpatch_ptrace_execute_until(proc, 1000, 0);
	if (ret < 0) {
		kperr("unable to run until libraries loaded\n");
		return -1;
	}

	return 1;
}

int
kpatch_process_execute_until_stop(kpatch_process_t *proc)
{
	int ret, pid, status = 0;
	struct kpatch_ptrace_ctx *pctx;

	for_each_thread(proc, pctx) {
		ret = ptrace(PTRACE_CONT, pctx->pid, NULL, NULL);
		if (ret < 0) {
			kplogerror("can't start tracee %d\n", pctx->pid);
			return -1;
		}
	}

	while (1) {
		pid = waitpid(-1, &status, __WALL);
		if (pid < 0) {
			kplogerror("can't wait any tracee\n");
			return -1;
		}

		if (WIFSTOPPED(status))  {
			if (WSTOPSIG(status) == SIGSTOP ||
			    WSTOPSIG(status) == SIGTRAP)
				return pid;
			status = WSTOPSIG(status);
			continue;
		}

		status = WIFSIGNALED(status) ? WTERMSIG(status) : 0;

		ret = ptrace(PTRACE_CONT, pid, NULL,
			     (void *)(uintptr_t)status);
		if (ret < 0) {
			kplogerror("can't start tracee %d\n", pid);
			return -1;
		}
	}

	return 0;
}

int
kpatch_process_init(kpatch_process_t *proc,
		    int pid,
		    int is_just_started,
		    int send_fd)
{
	int fdmaps;

	fdmaps = lock_process(pid);
	if (fdmaps < 0)
		goto out_err;

	memset(proc, 0, sizeof(*proc));

	proc->pid = pid;
	proc->fdmaps = fdmaps;
	proc->is_just_started = is_just_started;
	proc->send_fd = send_fd;
	proc->memfd = -1;

	list_init(&proc->ptrace.pctxs);
	kpatch_process_layout_init(&proc->layout);

	if (kpatch_coroutines_init(proc))
		goto out_unlock;
	if (process_get_comm(proc))
		goto out_unlock;

	return 0;

out_unlock:
	unlock_process(pid, fdmaps);
out_err:
	return -1;
}

void
kpatch_process_print_short(kpatch_process_t *proc)
{
	printf("kpatch_ctl targeting pid %d\n", proc->pid);
	if (proc->send_fd == -1) {
		printf("kpatch_ctl cmdline=\"");
		process_print_cmdline(proc);
		printf("\"\n");
	}
}

void
kpatch_process_free(kpatch_process_t *proc)
{
	unlock_process(proc->pid, proc->fdmaps);

	kpatch_process_layout_free(&proc->layout);

	kpatch_coroutines_free(proc);

	process_detach(proc);
	kpatch_process_destroy_object_files(proc);
}
