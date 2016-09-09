#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
int main(int argc, char *argv[])
{
	int ch_pid;
	int nr_child = atoi(argv[1]);
	for (int i = 0; i < nr_child; i++) {
		int pid = fork();
		if (!pid)
			break;
	}

	while (1)
		sleep(1);

	return 0;
}
