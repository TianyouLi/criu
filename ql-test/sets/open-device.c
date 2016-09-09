#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
int main()
{
	int fd = open("/dev/tty0", O_RDWR);
	struct stat stat;
	if (fstat(fd, &stat) < 0) {
		return -1;
	}
	printf("Is tty0: %d\n", S_ISCHR(stat.st_mode));
	if (fstat(0, &stat) < 0)
		return -1;

	printf("Is 0: %d\n", S_ISCHR(stat.st_mode));

	if (fstat(1, &stat) < 0)
		return -1;
	printf("Is 1: %d\n", S_ISCHR(stat.st_mode));

	if (fstat(2, &stat) < 0)
		return -1;
	printf("Is 2:%d\n", S_ISCHR(stat.st_mode));
	return 0;
}
