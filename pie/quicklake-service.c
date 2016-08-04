#include <string.h>
#include <errno.h>

#include "parasite.h"
#include "quicklake-service.h"
#include "syscall.h"
#include "log.h"
#include "asm/parasite.h"
#include "asm/restorer.h"

static int tsock = -1;
static struct rt_sigframe *sigframe;

static int ql_restore_files(void *data)
{
	return 0;
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
	//log_set_fd(-1);

	fini_sigreturn(new_sp);

	BUG();

	return -1;
}

static noinline int ql_unmap_blob(void *data)
{
	struct parasite_unmap_args *args = data;

	sys_munmap(args->parasite_start, args->parasite_len);

	BUG();
	return -1;
}

static int ql_daemon_reply_ack(unsigned int cmd, int err)
{
	struct ctl_msg m;
	int ret;

	m = ctl_msg_ack(cmd, err);
	ret = sys_sendto(tsock, &m, sizeof(m), 0, NULL, 0);
	if (ret != sizeof(m)) {
		pr_err("Sent only %d bytes while %zd expected\n", ret, sizeof(m));
		return -1;
	}

	pr_debug("__sent ack msg: %d %d %d\n", m.cmd, m.ack, m.err);

	return 0;
}

static int ql_daemon_wait_msg(struct ctl_msg *m)
{
	int ret;

	pr_debug("Daemon waits for command\n");

	while (1) {
		*m = (struct ctl_msg){ };
		ret = sys_recvfrom(tsock, m, sizeof(*m), MSG_WAITALL, NULL, 0);
		if (ret != sizeof(*m)) {
			pr_err("Trimmed message received (%d/%d)\n", (int)sizeof(*m), ret);
			return -1;
		}

		pr_debug("__fetched msg: %d %d %d\n", m->cmd, m->ack, m->err);
		return 0;
	}

	return -1;
}

static noinline __used int noinline ql_daemon(void *args)
{
	struct ctl_msg m = {};
	int ret = -1;

	pr_debug("Running quicklake daemon\n");

	if (ql_daemon_reply_ack(QUICKLAKE_CMD_INIT_DAEMON, 0))
		goto out;
	
	ret = 0;

	while (1) {
		if (ql_daemon_wait_msg(&m))
			break;

		if (ret && m.cmd != QUICKLAKE_CMD_FINI) {
			pr_err("Command rejected\n");
			continue;
		}

		switch (m.cmd) {
			case QUICKLAKE_CMD_FINI:
				goto out;
			case QUICKLAKE_CMD_RESTORE_FILES:
				ret = ql_restore_files(args);
				break;
			default:
				pr_err("Unknown command in quicklake daemon: %d\n", m.cmd);
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

static noinline __used int ql_init_daemon(void *data)
{
	struct parasite_init_args *args = data;
	int ret;

	args->sigreturn_addr = fini_sigreturn;
	sigframe = args->sigframe;
	tsock = sys_socket(PF_UNIX, SOCK_SEQPACKET, 0);
	if (tsock < 0) {
		pr_err("Can't create socket: %d\n", tsock);
		goto err;
	}

	ret = sys_connect(tsock, (struct sockaddr *) &args->h_addr, 
			args->h_addr_len);
	if (ret < 0) {
		pr_err("can't connect the control socket\n");
		goto err;
	}

	ret = recv_fd(tsock);
	if (ret >= 0) {
		//log_set_fd(ret);
		//log_set_loglevel(args->log_level);
		ret = 0;
	} else
		goto err;

	ql_daemon(data);

err:
	fini();
	BUG();
	return -1;
}

#ifndef __quicklake_entry
#define __quicklake_entry
#endif

int __used __quicklake_entry ql_service(unsigned int cmd, void *args)
{
	pr_info("Quicklake cmd %d/%x process\n", cmd, cmd);
	switch (cmd) {
		case QUICKLAKE_CMD_INIT_DAEMON:
			return ql_init_daemon(args);
		case QUICKLAKE_CMD_UNMAP:
			return ql_unmap_blob(args);
	}

	pr_err("Unknown quicklake command: %d\n", cmd);
	return -EINVAL;
}

