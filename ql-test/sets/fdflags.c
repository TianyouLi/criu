#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#define __USE_GNU	1
#include <fcntl.h>

int main()
{
	int fd = open("./temp.1", O_RDWR);
	if (fd < 0) {
		printf("Fail to open temp.1\n");
		return 0;
	}
	lseek(fd, 3, SEEK_CUR);
	if (fcntl(fd, F_SETFL, O_NONBLOCK))
		return 0;
	if (fcntl(fd, F_SETFD, FD_CLOEXEC))
		return 0;
	while (1) {
		sleep(1);
	}
}
