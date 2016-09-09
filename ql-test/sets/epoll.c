#include <sys/epoll.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

int main()
{
	int fd = epoll_create(2);
	int fd1 = open("./fifo.txt", O_RDWR);
	int fd2 = open("./fifo.txt", O_RDWR);
	struct epoll_event e1, e2;
	if (fd1 < 0 || fd2 < 0)
		return 0;
	e1.events = EPOLLIN | EPOLLET;
	e1.data.fd = fd1;
	if (epoll_ctl(fd, EPOLL_CTL_ADD, fd1, &e1)) {
		printf("%s\n", strerror(errno));
		return 0;
	}
	e2.data.fd = fd2;
	e2.events = EPOLLIN | EPOLLET;
	if (epoll_ctl(fd, EPOLL_CTL_ADD, fd2, &e2))
		return 0;
	while (1)
		sleep(1);
}
