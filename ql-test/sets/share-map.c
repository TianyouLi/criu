#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
int main()
{
	void *addr = mmap(NULL, 1024, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	int pid;

	pid = fork();
	if (pid < 0) {
		printf("Fail to fork\n");
		return 0;
	} else if (pid) {
		int val;
		while (1) {
			val = rand();
			sprintf(addr, "%d", val);
			sleep(1);
		}
	} else {
		int val;
		while (1) {
			sscanf(addr, "%d", &val);
			printf("%d\n", val);
			sleep(1);
		}
	}
}
