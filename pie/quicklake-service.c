#include <string.h>
#include <errno.h>
#include <sys/epoll.h>

#include "parasite.h"
#include "eventpoll.h"
#include "syscall.h"
#include "log.h"
#include "asm/parasite.h"
#include "asm/restorer.h"

static int tsock = -1;
static int logfd = -1;
static int retno;

static struct rt_sigframe *sigframe;

static int ql_daemon_reply_ack(unsigned int cmd, int err)
{
	struct ctl_msg m;

	m = ctl_msg_ack(cmd, err);
	retno = sys_sendto(tsock, &m, sizeof(m), 0, NULL, 0);
	if (retno != sizeof(m)) {
		pr_err("Sent only %d bytes while %zd expected\n", retno, sizeof(m));
		retno = -EINVAL;
		return retno;
	}

	pr_debug("__sent ack msg: %d %d %d\n", m.cmd, m.ack, m.err);

	return 0;
}

static int ql_daemon_wait_msg(struct ctl_msg *m)
{
	pr_debug("Daemon waits for command\n");

	while (1) {
		*m = (struct ctl_msg){ };
		retno = sys_recvfrom(tsock, m, sizeof(*m), MSG_WAITALL, NULL, 0);
		if (retno != sizeof(*m)) {
			pr_err("Trimmed message received (%d/%d)\n", (int) sizeof(*m),
					retno);
			retno = -EINVAL;
			return retno;
		}

		pr_debug("__fetched msg: %d %d %d\n", m->cmd, m->ack, m->err);
		return 0;
	}

	return -1;
}

static noinline void fini_sigreturn(unsigned long new_sp)
{
	ARCH_RT_SIGRETURN(new_sp);
}

static int fini()
{
	unsigned long new_sp;

	new_sp = (long)sigframe + SIGFRAME_OFFSET;
	pr_debug("%ld: new_sp=%lx ip %lx\n", sys_gettid(),
		  new_sp, RT_SIGFRAME_REGIP(sigframe));

	sys_close(tsock);
	log_set_fd(-1);

	fini_sigreturn(new_sp);

	BUG();

	return -1;
}

static int ql_reopen_fd_as(int old_fd, int new_fd, struct fd_opts *opt,
		bool allow_reuse_fd)
{
	if (old_fd != new_fd) {
		if (!allow_reuse_fd) {
			if (sys_fcntl(new_fd, F_GETFD, 0) != -EBADF) {
				ql_debug("new fd %d already in use (old fd:%d)\n", new_fd,
						old_fd);
				retno = -EEXIST;
				return retno;
			}
		}
		retno = sys_dup2(old_fd, new_fd);
		if (retno < 0) {
			ql_debug("Fail to dup fd %d as %d\n", old_fd, new_fd);
			return retno;
		}

		retno = sys_close(old_fd);
		if (retno) {
			ql_debug("Fail to close old fd %d\n", old_fd);
			return retno;
		}

		if (opt) {
			retno = sys_fcntl(new_fd, F_SETFD, opt->flags);
			if (retno) {
				ql_debug("Fail to set fd(%d) flags(%d)\n", new_fd, opt->flags);
				return retno;
			}
		}
	}
	return 0;
}

static int ql_restore_epoll_add(struct epoll_arg *epoll_arg)
{
	struct epoll_event event;
	int i;
	int fd = epoll_arg->epoll_fd;

	ql_debug("Restore epoll fd %d\n", fd);
	for (i = 0; i < epoll_arg->nr_fd; i++) {
		event.events = epoll_arg->p[i].event;
		event.data.u64 = epoll_arg->p[i].event_data;
		retno = sys_epoll_ctl(fd, EPOLL_CTL_ADD, epoll_arg->p[i].fd, &event);
		if (retno) {
			pr_err("Can't add eventpoll of %d on %d(%d)\n", fd,
					epoll_arg->p[i].fd, retno);
			return retno;
		}
	}
	return 0;
}

// restore eventpoll, sk-inet, sk-unix, timerfd, 'tty' after reopen
//FIXME: We assume that value of fds and args->fds are in order
static int ql_restore_files(struct parasite_drain_fd *args)
{
	int max_fd = 0, i;
	int fds[PARASITE_MAX_FDS];
	struct fd_opts opts[PARASITE_MAX_FDS];

	if (ql_daemon_reply_ack(QUICKLAKE_CMD_RESTORE_FILE, 0))
		return retno;

	if (recv_fds(tsock, fds, args->nr_fds, opts))
		return retno;

	/* redirect tsock and log fd which may clash with args->fds */
	max_fd = args->fds[args->nr_fds - 1] > fds[args->nr_fds - 1] ?
			args->fds[args->nr_fds - 1] : fds[args->nr_fds - 1];
	ql_debug("Now dup tsock %d->%d, log fd %d->%d\n", tsock, max_fd + 1,
			logfd, max_fd + 2);

	if (ql_reopen_fd_as(tsock, max_fd + 1, NULL, false)) {
		pr_err("Can't dup tsock %d->%d\n", tsock, max_fd + 1);
		return retno;
	}
	tsock = max_fd + 1;

	if (ql_reopen_fd_as(logfd, max_fd + 2, NULL, false)) {
		pr_err("Can't dup logfd %d->%d\n", logfd, max_fd + 2);
		return retno;
	}
	logfd = max_fd + 2;
	log_set_fd(logfd);

	/* The method I use is similar to the restore of VMA in last stage. */
	for (i = 0; i < args->nr_fds; i++) {
		if (args->fds[i] <= fds[i]) {
			if (ql_reopen_fd_as(fds[i], args->fds[i], opts + i, false))
				return retno;
		} else
			break;
	}
	for (i = args->nr_fds - 1; i >= 0; --i) {
		if (args->fds[i] > fds[i]) {
			if (ql_reopen_fd_as(fds[i], args->fds[i], opts + i, false))
				return retno;
		} else
			break;
	}

	return 0;
}

static noinline __used int noinline ql_daemon(void *args)
{
	struct ctl_msg m = { };
	int ret = -1;

	pr_debug("Running daemon thread leader\n");

	/* Reply we're alive */
	if (ql_daemon_reply_ack(PARASITE_CMD_INIT_DAEMON, 0))
		goto out;

	ret = 0;

	while (1) {
		if (ql_daemon_wait_msg(&m))
			break;

		if (ret && m.cmd != PARASITE_CMD_FINI) {
			pr_err("Command rejected\n");
			continue;
		}

		switch (m.cmd) {
		case PARASITE_CMD_FINI:
			goto out;
		case QUICKLAKE_CMD_RESTORE_FILE:
			ret = ql_restore_files(args);
			break;
		case QUICKLAKE_CMD_EPOLL_ADD:
			ret = ql_restore_epoll_add(args);
			break;
		default:
			pr_err("Unknown command in parasite daemon thread leader: %d\n", m.cmd);
			ret = -1;
			break;
		}

		if (ql_daemon_reply_ack(m.cmd, ret))
			break;

		if (ret) {
			pr_err("Close the control socket for writing\n");
			sys_shutdown(tsock, SHUT_WR);
		}
	}

out:
	fini();

	return 0;
}

static noinline int ql_unmap_blob(void *data)
{
	struct parasite_unmap_args *args = data;

	sys_munmap(args->parasite_start, args->parasite_len);
	/*
	 * This call to sys_munmap must never return. Instead, the controlling
	 * process must trap us on the exit from munmap.
	 */

	BUG();
	return -1;
}

static noinline __used int ql_init_daemon(void *data)
{
	struct parasite_init_args *args = data;

	args->sigreturn_addr = fini_sigreturn;
	sigframe = args->sigframe;

	tsock = sys_socket(PF_UNIX, SOCK_SEQPACKET, 0);
	if (tsock < 0) {
		pr_err("Can't create socket: %d\n", tsock);
		retno = tsock;
		goto err;
	}

	retno = sys_connect(tsock, (struct sockaddr *)&args->h_addr, 
			args->h_addr_len);
	if (retno < 0) {
		pr_err("Can't connect the control socket\n");
		goto err;
	}

	logfd = recv_fd(tsock);
	if (logfd >= 0) {
		log_set_fd(logfd);
		log_set_loglevel(args->log_level);
		retno = 0;
	} else
		goto err;

	ql_daemon(data);

err:
	fini();
	BUG();

	return retno;
}

#ifndef quicklake_entry
#define quicklake_entry
#endif

int __used quicklake_entry ql_service(unsigned int cmd, void *args)
{
	pr_info("Parasite cmd %d/%x process\n", cmd, cmd);
	switch (cmd) {
	case PARASITE_CMD_INIT_DAEMON:
		return ql_init_daemon(args);
	case PARASITE_CMD_UNMAP:
		return ql_unmap_blob(args);
	}

	pr_err("Unknown command to parasite: %d\n", cmd);
	return -EINVAL;
}
