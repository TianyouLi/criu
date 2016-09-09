#include <unistd.h>
#include <stdio.h>
int main()
{
	int ch_pid;
	ch_pid = fork();

	if (ch_pid == 0) {
		printf("This is children\n");
		return 0;
	} else if (ch_pid > 0) {
		printf("This is parent\n");
		while (1)
			sleep(1);
	}
	return 0;
}
