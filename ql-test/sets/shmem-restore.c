#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
int main()
{
	void *addr = mmap(NULL, 1024, PROT_READ | PROT_WRITE | PROT_EXEC, 
			MAP_ANONYMOUS|MAP_SHARED,-1,0);
	char filename[1024];
	int fd, i = 0;

	sprintf(filename, "/proc/self/map_files/%llx-%llx", addr,
			addr + 4096);
	printf("%s\n", filename);
	fd = open(filename, O_RDWR);
	munmap(addr, 1024);
	if (fd < 0) {
		printf("Fail to open\n");
	}
	while (1) {
		sleep(1);
//		if (i++ == 20)
//			munmap(addr, 1024);
	}
}
