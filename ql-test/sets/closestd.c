#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

int main()
{
	printf("close stdout\n");
	int ret = close(1);
	if (ret)
		return ret;
	int fd = open("/dev/pts/5", O_RDWR);
	if (fd<0)return fd;
	printf("open stdout\n");
	while(1)sleep(1);
}
