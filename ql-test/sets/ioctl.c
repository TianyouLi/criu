#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
	int fd = open(argv[1], O_RDWR);
	if (fd < 0) {
		printf("Fail to open file\n");
		return 0;
	}
	ioctl(fd, atoi(argv[2]));
	close(fd);
	return 0;
}
