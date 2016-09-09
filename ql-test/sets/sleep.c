#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
int main()
{
	int i = 0;
	while (1) {
		printf("%d\n",i++);
		sleep(1);
	}
}
