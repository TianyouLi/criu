#include <aio.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <error.h>
#include <signal.h>
struct aiocb aiocb;
void aio_handler(int signo, siginfo_t *info, void *context)
{
	if (info->si_signo == SIGIO) {
		struct aiocb *req = (struct aiocb *)info->si_value.sival_ptr;
		if (!aio_error(req)) {
			printf("---%s\n", req->aio_buf);
			aio_read(req);
		}

	}
}
int main(int argc, char *argv[])
{
	int fd, ret;
	struct sigaction sigact;

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		printf("Open error %s\n", argv[1]);
		exit(0);
	}

	printf("Open %s\n", argv[1]);
	memset(&aiocb, 0, sizeof(struct aiocb));
	aiocb.aio_buf = malloc(1024);
	if (!aiocb.aio_buf) {
		exit(0);
	}

	sigemptyset(&sigact.sa_mask);
	sigact.sa_flags = SA_SIGINFO;
	sigact.sa_sigaction = aio_handler;

	aiocb.aio_fildes = fd;
	aiocb.aio_nbytes = 1024;
	aiocb.aio_offset = 0;
	aiocb.aio_sigevent.sigev_notify = SIGEV_SIGNAL;
	aiocb.aio_sigevent.sigev_signo = SIGIO;
	aiocb.aio_sigevent.sigev_value.sival_ptr = &aiocb;
	ret = sigaction(SIGIO, &sigact, NULL);

	ret = aio_read(&aiocb);
	while (1)
		sleep(1);
}
