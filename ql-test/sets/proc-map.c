#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
int main(int argc, char *argv[])
{
	int pid, fd;
	unsigned long start, end;
	char filename[1024];
	void *addr;
	if (argc != 4) {
		printf("Usage: ./prog pid start end");
		return 0;
	}

	sprintf(filename, "/proc/%s/map_files/%s-%s", argv[1], argv[2], argv[3]);
	fd = open(filename, O_RDWR);
	if (fd < 0) {
		printf("Fail to open\n");
		return 0;
	}
	addr = mmap(NULL, 1024, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (!addr) {
		printf("Fail to mmap\n");
		return 0;
	}
	close(fd);
	while (1) {
		int *val = addr;
		printf("%d\n", *val);
		sleep(1);
	}
	return 0;
}
