#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include "parasite.h"
#include "quicklake-blob.h"
#include "parasite-syscall.h"
#include "vma.h"
#include "pstree.h"
#include "ptrace.h"
#include "util.h"
#include "quicklake.h"
#include "protobuf.h"
#include "asm/restorer.h"
#include "pie/pie-relocs.h"
#include "namespaces.h"
#include "asm/dump.h"
#include "seize.h"
#include "net.h"
/* Required by cinfos */
#include "sk-inet.h"
#include "files-reg.h"
#include "pipes.h"
#include "timerfd.h"
#include "signalfd.h"
#include "file-lock.h"
#include "sk-packet.h"
#include "tun.h"
#include "eventpoll.h"
#include "tty.h"
#include "fifo.h"
#include "eventfd.h"
#include "fsnotify.h"

static unsigned long parasite_args_size = PARASITE_ARG_SIZE_MIN;
static struct pstree_item **items = NULL;
static int nr_item = 0;
int quicklake_task_state = QL_TASK_STATE_NONE;

struct ql_restore_state {
	char *name;
	int (*restore_pstree_item) (struct pstree_item *pi);
	bool no_loop;
};

int switch_ql_state(pid_t pid, int request)
{
	int fd = open_proc_rw(pid, "crstat");
	
	if (fd < 0)
		return -1;
	if (ioctl(fd, request))
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

	BUG_ON(item->threads[0].virt != pid);

	/* Search area for mmap system call */
	ctl = parasite_prep_ctl(pid, vma_area_list);
	if (!ctl)
		return NULL;
	/* check size of dfds */
	parasite_ensure_args_size(drain_fds_size(&(qli(item)->dfds)));
	/* check size of epoll */
	parasite_ensure_args_size(parasite_epoll_size(qli(item)->nr_max_epolls));
	/* check size of timerfd */
	parasite_ensure_args_size(parasite_timerfd_size(qli(item)->nr_timerfd));
	/* check sk tcp size */
	parasite_ensure_args_size(parasite_sk_tcp_size(qli(item)->nr_sk_tcp));

	ctl->args_size = round_up(parasite_args_size, PAGE_SIZE);
	ctl->pid.real = pid;
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

	if (parasite_start_daemon(ctl, item)) {
		goto err_restore;
	}

	return ctl;

err_restore:
	parasite_cure_seized(ctl);
	return NULL;
}

static int ql_open_fdinfos(struct pstree_item *pi, struct list_head *list)
{
	struct fdinfo_list_entry *fle;
	struct parasite_drain_fd *dfds = &(qli(pi)->dfds);

	list_for_each_entry(fle, list, ps_list) {
		struct file_desc *d = fle->desc;
		int fd;

		dfds->fds[dfds->nr_fds++] = fle->fe->fd;
		if (fle != file_master(d))
			continue;

		fd = d->ops->open(d);
		if (fd < 0)
			return -1;
		d->new_fd = fd;
		if (d->ops->type == FD_TYPES__TIMERFD) {
			ql_add_timerfd_info(pi, d, fle->fe->fd);
		} else if (d->ops->type == FD_TYPES__INETSK) {
			ql_add_sk_tcp_info(pi, d, fle->fe->fd);
		}
	}
	return 0;
}

static int ql_prepare_files(struct pstree_item *pi)
{
	struct fdinfo_list_entry *fle;
	INIT_LIST_HEAD(&qli(pi)->timerfd_list);

	if (rsti(pi)->fdt && rsti(pi)->fdt->pid != pi->pid.virt) {
		pr_info("File descriptor table is shared with %d\n", rsti(pi)->fdt->pid);
		goto stop;
	}

	if (ql_open_fdinfos(pi, &rsti(pi)->fds))
		return -1;

	if (ql_open_fdinfos(pi, &rsti(pi)->eventpoll))
		return -1;

	list_for_each_entry(fle, &rsti(pi)->eventpoll, ps_list) {
		int count = eventpoll_count_tfds(fle->desc);
		qli(pi)->nr_max_epolls = qli(pi)->nr_max_epolls < count ? count :
				qli(pi)->nr_max_epolls;
	}
	//TODO: handle tty
stop:
	return 0;
}

static int ql_post_prepare_files(struct pstree_item *pi)
{
	struct fdinfo_list_entry *fle;

	if (rsti(pi)->fdt && rsti(pi)->fdt->pid != pi->pid.virt)
		return 0;

	list_for_each_entry(fle, &rsti(pi)->fds, ps_list) {
		if (post_open_fd(pi->pid.virt, fle))
			return -1;
	}
	return 0;
}

static int parasite_repair_sk_tcp(struct parasite_ctl *ctl,
		struct pstree_item *pi)
{
	int sk_size, ret;
	void *sk_tcp;

	if (!qli(pi)->nr_sk_tcp)
		return 0;

	sk_size = parasite_sk_tcp_size(qli(pi)->nr_sk_tcp);
	sk_tcp = parasite_args_s(ctl, sk_size);

	ql_collect_sk_tcp(pi, sk_tcp);

	ret = __parasite_execute_daemon(QUICKLAKE_CMD_REPAIR_TCP, ctl);
	if (ret) {
		pr_err("Can't repair tcp %d\n", ret);
		return ret;
	}

	ret = __parasite_wait_daemon_ack(QUICKLAKE_CMD_REPAIR_TCP, ctl);
	if (ret) {
		pr_err("Can't wait ack of repair tcp\n");
		return ret;
	}
	return 0;
}

static int parasite_start_timerfd(struct parasite_ctl *ctl,
		struct pstree_item *pi)
{
	int tf_size, ret;
	void *tf;

	if (!qli(pi)->nr_timerfd)
		return 0;

	tf_size = parasite_timerfd_size(qli(pi)->nr_timerfd);
	tf = parasite_args_s(ctl, tf_size);

	ql_collect_timerfd_info(pi, tf);

	ret = __parasite_execute_daemon(QUICKLAKE_CMD_START_TIMERFD, ctl);
	if (ret) {
		pr_err("Can't start timerfd %d\n", ret);
		return ret;
	}

	ret = __parasite_wait_daemon_ack(QUICKLAKE_CMD_START_TIMERFD, ctl);
	if (ret) {
		pr_err("Can't wait ack of start timerfd\n");
		return ret;
	}
	return 0;
}

static int parasite_add_epoll(struct parasite_ctl *ctl, struct pstree_item *pi)
{
	struct fdinfo_list_entry *fle;
	struct epoll_arg *epoll_arg;
	int epoll_size;
	int ret;

	list_for_each_entry(fle, &rsti(pi)->eventpoll, ps_list) {
		int nr_epoll_fd = eventpoll_count_tfds(fle->desc);

		if (!nr_epoll_fd || fle != file_master(fle->desc))
			continue;

		epoll_size = parasite_epoll_size(nr_epoll_fd);
		epoll_arg = parasite_args_s(ctl, epoll_size);
		epoll_arg->epoll_fd = fle->fe->fd;
		epoll_arg->nr_fd = nr_epoll_fd;
		eventpoll_collect_args(fle->desc, epoll_arg);

		ret = __parasite_execute_daemon(QUICKLAKE_CMD_EPOLL_ADD, ctl);
		if (ret) {
			pr_err("Can't epoll %d add tfd", epoll_arg->epoll_fd);
			return ret;
		}

		ret = __parasite_wait_daemon_ack(QUICKLAKE_CMD_EPOLL_ADD, ctl);
		if (ret) {
			pr_err("Can't wait epoll ack %d\n", epoll_arg->epoll_fd);
			return ret;
		}
	}
	return 0;
}

static int parasite_send_fds(struct parasite_ctl *ctl, struct pstree_item *pi)
{
	int ret = -1, size, *new_fds = NULL, nr_new_fds = 0;
	struct parasite_drain_fd *args, *dfds;
	struct fdinfo_list_entry *fle;

	pr_info("pid %d send %d fds to remote\n", pi->pid.virt,
			qli(pi)->dfds.nr_fds);
	dfds = &(qli(pi)->dfds);
	if (!dfds->nr_fds)
		return 0;

	size = drain_fds_size(dfds);
	args = parasite_args_s(ctl, size);
	memcpy(args, dfds, size);

	ret = __parasite_execute_daemon(QUICKLAKE_CMD_RESTORE_FILE, ctl);
	if (ret) {
		pr_err("Parasite failed to sync restore_files\n");
		goto err;
	}

	ret = __parasite_wait_daemon_ack(QUICKLAKE_CMD_RESTORE_FILE, ctl);
	if (ret)
		goto err;

	new_fds = xmalloc(size);
	if (!new_fds) {
		pr_err("Fail to allocate new fds\n");
		ret = -1;
		goto err;
	}

	list_for_each_entry(fle, &rsti(pi)->fds, ps_list) {
		new_fds[nr_new_fds++] = fle->desc->new_fd;
		if (fcntl(fle->desc->new_fd, F_SETFD, fle->fe->flags) == -1) {
			pr_err("Fail to set fd %d flags\n", fle->desc->new_fd);
			return -1;
		}
	}
	list_for_each_entry(fle, &rsti(pi)->eventpoll, ps_list) {
		new_fds[nr_new_fds++] = fle->desc->new_fd;
		if (fcntl(fle->desc->new_fd, F_SETFD, fle->fe->flags) == -1) {
			pr_err("Fail to set fd %d flags\n", fle->desc->new_fd);
			return -1;
		}
	}

	BUG_ON(nr_new_fds != dfds->nr_fds);
	ret = send_fds(ctl->tsock, NULL, 0, new_fds, nr_new_fds, true);
	if (ret) {
		pr_err("Fail to send fds\n");
		goto err;
	}

	ret = __parasite_wait_daemon_ack(QUICKLAKE_CMD_RESTORE_FILE, ctl);
	if (ret)
		goto err;

	/* mask SIGCHLD */
	{
		struct sigaction sa = {
			.sa_handler = SIG_DFL,
			.sa_flags = SA_SIGINFO | SA_RESTART,
		};

		sigemptyset(&sa.sa_mask);
		sigaddset(&sa.sa_mask, SIGCHLD);
		if (sigaction(SIGCHLD, &sa, NULL)) {
			pr_err("Unable to mask SIGCHLD\n");
			ret = 1;
		}
	}

err:
	if (new_fds)
		xfree(new_fds);
	return ret;
}

static int ql_cure_parasite_task(struct pstree_item *item)
{
	struct parasite_ctl *ctl = qli(item)->parasite_ctl;
	pid_t ori_real = item->pid.real;

	if (parasite_stop_daemon(ctl)) {
		pr_err("Can't stop daemon (pid: %d) from ql parasite\n",
				item->pid.virt);
		return -EPERM;
	}

	if (parasite_cure_seized(ctl)) {
		pr_err("Can't cure (pid: %d) from ql parasite\n",
				item->pid.virt);
		return -EPERM;
	}

	item->pid.real = item->pid.virt;
	BUG_ON(item->state > TASK_STOPPED);
	unseize_task_and_threads(item, item->state);
	item->pid.real = ori_real;

	return 0;
}

/* Restore task in quicklake state */
static int ql_restore_one_task(struct pstree_item *item)
{
	struct vm_area_list vmas;
	pid_t pid = item->pid.virt;
	struct parasite_ctl *parasite_ctl;
	int ret;
	struct cr_img *img;
	CoreEntry *core_entry;

	INIT_LIST_HEAD(&vmas.h);
	vmas.nr = 0;

	pr_info("========================================\n");
	pr_info("Restoring quicklake task (pid: %d)\n", pid);
	pr_info("========================================\n");

	/* zombies are restored later */
	if (item->state == TASK_DEAD)
		return 0;

	/* Load core info */
	img = open_image(CR_FD_CORE, O_RSTR, item->pid.virt);
	if (!img)
		goto stop;
	ret = pb_read_one(img, &core_entry, PB_CORE);
	close_image(img);
	if (ret < 0)
		goto stop;
	item->core = &core_entry;

	/*
	 * We collect mappings for parasite code injection. We can save the address
	 * of parasite code in checkpoint
	 */
	ret = collect_mappings(pid, &vmas);
	if (ret) {
		pr_err("Collect mappings (pid: %d) failed with %d\n", pid, ret);
		goto stop;
	}

	/* Attach to ql task*/
	parasite_ctl = parasite_seized(pid, item, &vmas);
	if (!parasite_ctl) {
		pr_err("Can't infect (pid: %d) with ql parasite\n", pid);
		ret = -1;
		goto stop;
	}

	qli(item)->parasite_ctl = parasite_ctl;
	ret = parasite_send_fds(parasite_ctl, item);
	if (ret) {
		pr_err("Can't send fds of pid(%d) with ql parasite: %s\n", pid,
				strerror(-ret));
		goto stop;
	}

	ret = parasite_add_epoll(parasite_ctl, item);
	if (ret) {
		pr_err("Can' t add epolls of pid(%d): %s\n", pid, strerror(-ret));
		goto stop;
	}

	ret = parasite_start_timerfd(parasite_ctl, item);
	if (ret) {
		pr_err("Can't start %d of timerfd: %s\n", pid, strerror(-ret));
		goto stop;
	}

	ret = parasite_repair_sk_tcp(parasite_ctl, item);
	if (ret) {
		pr_err("Can't repair tcp of pid %d: %s\n", pid, strerror(-ret));
		goto stop;
	}

stop:
	free_mappings(&vmas);
	return ret;
}

static int wakeup_ql_task(int tid)
{
	struct proc_status_creds *creds = NULL;
	int ret = switch_ql_state(tid, IOC_QL_RESTORE);
	pr_info("Wake up tid %d\n", tid);
	if (ret) return -1;
	ret = seize_catch_task(tid);
	if (ret) return -1;
	ret = seize_wait_task(tid, -1, &creds);
	xfree(creds);
	return ret;
}

static int ql_freeze_process(struct pstree_item *pi)
{
	/*
	 * TODO: the ql-task should stop after switching to
	 * QL_RESTORE state and before we seize it.
	 */
	int i;
	pi->state = wakeup_ql_task(pi->pid.virt);
	if (pi->state < 0) {
		pr_err("Fail to wake up ql task: %d\n", pi->pid.virt);
		return -1;
	}

	for (i = 0; i < pi->nr_threads; i++) {
		if (pi->threads[i].virt != pi->pid.virt) {
			if (wakeup_ql_task(pi->threads[i].virt) < 0) {
				pr_err("Fail to wake up thread %d of pid %d\n",
						pi->threads[i].virt, pi->pid.virt);
				return -1;
			}
		}
	}
	return 0;
}

static struct collect_image_info *cinfos[] = {
	&reg_file_cinfo,
	&remap_cinfo,
	&nsfile_cinfo,
	&pipe_cinfo,
	&fifo_cinfo,
	&unix_sk_cinfo,
	&packet_sk_cinfo,
	&netlink_sk_cinfo,
	&eventfd_cinfo,
	&epoll_tfd_cinfo,
	&epoll_cinfo,
	&signalfd_cinfo,
	&inotify_cinfo,
	&inotify_mark_cinfo,
	&fanotify_cinfo,
	&fanotify_mark_cinfo,
	&tty_info_cinfo,
	&tty_cinfo,
	&tunfile_cinfo,
	&ext_file_cinfo,
	&timerfd_cinfo,
	&file_locks_cinfo,
};

static int ql_collect_file_images(void)
{
	int i;

	/* init file_desc_hash */
	if (prepare_shared_fdinfo())
		return -1;

	if (collect_inet_sockets())
		return -1;

	for (i = 0; i < ARRAY_SIZE(cinfos); ++i) {
		unsigned flags = cinfos[i]->flags;
		int ret;

		/* change flags of unix_sk_cinfo */
		cinfos[i]->flags &= ~COLLECT_SHARED;
		ret = collect_image(cinfos[i]);
		cinfos[i]->flags = flags;
		if (ret)
			return -1;
	}

	if (collect_pipes())
		return -1;

	if (collect_fifo())
		return -1;

	if (collect_unix_sockets())
		return -1;

	return 0;
}

/* Collect open fd for each process and setup parasite socket */
static int ql_collect_fds(struct pstree_item *pi)
{
	if (prepare_fd_pid(pi) < 0)
		return -1;
	pr_info("Generate socket for pid: %d\n", pi->pid.virt);
	dmpi(pi)->netns = xmalloc(sizeof(struct ns_id));
	//FIXME: Is it ok that we don't init netns ?
	dmpi(pi)->netns->net.seqsk = socket(PF_UNIX, SOCK_SEQPACKET, 0);
	if (dmpi(pi)->netns->net.seqsk < 0) {
		pr_err("Can't create seqsk for ql parasite\n");
		return -1;
	}
	return 0;
}

/* determine which process is responsible for creating fd-pairs */
static int ql_resolve_file_master(struct pstree_item *pi)
{
	BUG_ON(pi);
	mark_pipe_master();
	//TODO: how to handle tty
	if (resolve_unix_peers())
		return -1;
	return 0;
}

static int ql_prepare_namespace(void)
{
	pr_info("Restore namespace\n");
	if (prepare_mnt_ns())
		return -1;
	return 0;
}

static int sort_pstree_item()
{
	struct pstree_item *item;
	int i = 0, j;

	items = xmalloc(sizeof(item) * nr_item);
	if (!items)
		return -ENOMEM;

	for_each_pstree_item(item)
		items[i++] = item;

	for (i = 0; i < nr_item - 1; i++) {
		item = items[i + 1];
		for (j = i; j >= 0; --j) {
			if (pid_rst_prio(item->pid.virt, items[j]->pid.virt)) {
				items[j + 1] = items[j];
			} else break;
		}
		items[j + 1] = item;
	}

	return 0;
}

static int ql_unlock_network(struct pstree_item *pi)
{
	BUG_ON(pi);
	network_unlock();
	return 0;
}

static struct ql_restore_state rst_states[] = {
	{"collect fds", ql_collect_fds, false},
	{"resolve file master", ql_resolve_file_master, true},
	{"freeze pstree", ql_freeze_process, false},
	{"open files", ql_prepare_files, false},
	{"post-open files", ql_post_prepare_files, false},
	{"restore task", ql_restore_one_task, false},
	{"unlock network", ql_unlock_network, true},
	{"post-restore task", ql_cure_parasite_task, false},
};

int restore_ql_task()
{
	int ret, i, j;

	ret = ql_read_pstree_image(&nr_item);
	if (ret < 0) goto err;

	ret = prepare_pstree_kobj_ids();
	if (ret) goto err;

	ret = ql_prepare_namespace();
	if (ret) goto err;

	ret = sort_pstree_item(nr_item);
	if (ret) goto err;

	if (ql_collect_file_images() < 0) {
		pr_err("Can't prepare shared info\n");
		goto err;
	}

	for (i = 0; i < ARRAY_SIZE(rst_states); i++) {
		pr_info("Enter restore state: %s\n", rst_states[i].name);
		if (rst_states[i].no_loop) {
			ret = rst_states[i].restore_pstree_item(NULL);
			if (ret) goto err;
			continue;
		}

		for (j = 0; j < nr_item; j++) {
			BUG_ON(j + 1 < nr_item && items[j]->pid.virt >
					items[j + 1]->pid.virt);
			ret = rst_states[i].restore_pstree_item(items[j]);
			if (ret) goto err;
		}
	}

	pr_info("Restore quicklake task successfully!!!\n");
err:
	xfree(items);
	items = NULL;
	return ret;
}
