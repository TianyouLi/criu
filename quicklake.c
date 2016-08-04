#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include "parasite.h"
#include "parasite-syscall.h"
#include "quicklake-blob.h"
#include "vma.h"
#include "pstree.h"
#include "util.h"
#include "quicklake.h"
#include "asm/restorer.h"
#include "pie/pie-relocs.h"

static unsigned long parasite_args_size = PARASITE_ARG_SIZE_MIN;
int switch_ql_state(pid_t pid)
{
	int fd = open_proc_rw(pid, "crstat");
	
	if (fd < 0)
		return -1;
	if (ioctl(fd, QL_DUMP))
		return -1;
	close(fd);
	return 0;
}

static struct parasite_ctl *parasite_seized(pid_t pid, struct pstree_item *item,
		struct vm_area_list *vma_area_list)
{
	int ret;
	struct parasite_ctl *ctl;
	unsigned long p, map_exchange_size;

	BUG_ON(item->threads[0].real != pid);

	/* Search area for mmap system call */
	ctl = parasite_prep_ctl(pid, vma_area_list);
	if (!ctl)
		return NULL;
	//TODO: check argument size

	ctl->args_size = round_up(parasite_args_size, PAGE_SIZE);
	parasite_args_size = PARASITE_ARG_SIZE_MIN; /* reset for next task */
	map_exchange_size = pie_size(quicklake_blob) + ctl->args_size;
	map_exchange_size += RESTORE_STACK_SIGFRAME + PARASITE_STACK_SIZE;
	if (item->nr_threads > 1)
		map_exchange_size += PARASITE_STACK_SIZE;

	memcpy(&item->core[0]->tc->blk_sigset, &ctl->orig.sigmask,
			sizeof(k_rtsigset_t));

	ret = parasite_map_exchange(ctl, map_exchange_size);
	if (ret)
		goto err_restore;

	pr_info("Putting parasite blob into %p->%p\n", ctl->local_map, ctl->remote_map);
	memcpy(ctl->local_map, quicklake_blob, sizeof(quicklake_blob));

	elf_relocs_apply(ctl->local_map, ctl->remote_map, sizeof(quicklake_blob),
			quicklake_relocs, ARRAY_SIZE(quicklake_relocs));

	/* Setup the rest of a control block */
	ctl->parasite_ip = (unsigned long) ql_sym(ctl->remote_map,
			__export_parasite_head_start);
	ctl->addr_cmd = ql_sym(ctl->local_map, __export_parasite_cmd);
	ctl->addr_args = ql_sym(ctl->local_map, __export_parasite_args);

	p = pie_size(quicklake_blob) + ctl->args_size;

	ctl->rsigframe = ctl->remote_map + p;
	ctl->sigframe = ctl->local_map  + p;

	p += RESTORE_STACK_SIGFRAME;
	p += PARASITE_STACK_SIZE;
	ctl->rstack = ctl->remote_map + p;

	if (item->nr_threads > 1) {
		p += PARASITE_STACK_SIZE;
		ctl->r_thread_stack = ctl->remote_map + p;
	}

	if (parasite_start_daemon(ctl, item))
		goto err_restore;

	return ctl;

err_restore:
	parasite_cure_seized(ctl);
	return NULL;
}

/* Restore task in quicklake state */
static int ql_restore_one_task(struct pstree_item *item)
{
	struct vm_area_list vmas;
	pid_t pid = item->pid.real;
	struct parasite_ctl *parasite_ctl;
	int ret, exit_code = -1;

	INIT_LIST_HEAD(&vmas.h);
	vmas.nr = 0;

	pr_info("========================================\n");
	pr_info("Restoring quicklake task (pid: %d)\n", pid);
	pr_info("========================================\n");

	/* zombies are restored later */
	if (item->state == TASK_DEAD)
		return 0;

	/*
	 * We collect mappings for parasite code injection. We can save the address
	 * of parasite code in checkpoint
	 */
	ret = collect_mappings(pid, &vmas);
	if (ret) {
		pr_err("Collect mappings (pid: %d) failed with %d\n", pid, ret);
		goto err;
	}

	//TODO
	/* shared file tables need to be restore in kernel */

	/* Attach to ql task*/
	parasite_ctl = parasite_seized(pid, item, &vmas);
	if (!parasite_ctl) {
		pr_err("Can't infect (pid: %d) with ql parasite\n", pid);
		goto err;
	}

	//TODO: restore ...


	exit_code = 0;
err:
	free_mappings(&vmas);
	return exit_code;
}
