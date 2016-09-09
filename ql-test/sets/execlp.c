#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <string.h>

int main(int argc, char *argv[])
{
	int i = 0;
	int nr_child = atoi(argv[1]);
	int *pids = malloc(sizeof(int) * nr_child);
	for (i = 0; i < nr_child; i++) {
		pids[i] = fork();
		if (pids[i] < 0)
			exit(0);
		else if (!pids[i]) {
			int ret = execlp("./slow-load", "slow-load", (char *) 0);
			if (ret)
				exit(0);
		}
		printf("execlp %d\n", pids[i]);
	}
	for (i = 0; i < nr_child; i++) {
		int status = 0;
		waitpid(pids[i], &status, 0);
		printf("wait %d\n", pids[i]);
	}
	return 0;
}
