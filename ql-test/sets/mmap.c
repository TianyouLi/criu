#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
int main()
{
	void *addr = mmap(NULL, 1024, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_SHARED,-1,0);
	printf("%p\n",addr);
	while (1) {
		*((int *) addr) = rand();
		printf("%d\n", *((int *) addr));
		sleep(1);
		pp
	}
}
