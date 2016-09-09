#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#include "util.h"

#define sk_path	"/root/prog/tmp/sk-unix"

int run_child_client(void *arg)
{
	int tid = syscall(__NR_gettid);
	int sk = connect_to_unix(sk_path);
	if (sk < 0)
		return 0;
	int num = 0;
	do {
		int len = read(sk, &num, sizeof(num));
		int ret = write(sk, &num, sizeof(num));
		ptf("%d-unix: recv %d send %d ret(%d:%s)\n", tid, num, num, ret, strerror(errno));
		sleep(10);
	} while (num);
	return 0;
}

int run_child_server(void *arg)
{
	int num;
	int tid = syscall(__NR_gettid);
	int sk = *(int *)arg;

	srand((long)&num);
	do {
		num = rand() + 1;
		int ret = write(sk, &num, sizeof(num));
		read(sk, &num, sizeof(num));
		ptf("%d-unix: send %d recv %d ret(%d:%s)\n", tid, num, num, ret, strerror(errno));
	} while (num);
	return 0;
}

int main()
{
	int server_sk = create_unix_server(sk_path);
	int nr_child = 1;

	while (nr_child--) {
		struct sockaddr_un client_addr;
		socklen_t length = sizeof(client_addr);
		void *stack = malloc(102400);
		
		int pid = clone(run_child_client, stack + 102400, 0, NULL);

		int new_sk = accept(server_sk, (struct sockaddr *) &client_addr, &length);
		if (new_sk < 0)
			continue;
		stack = malloc(102400);
		pid = clone(run_child_server, stack + 102400, 0, &new_sk);
	}
	while (1)
		sleep(2000);
	return 0;
}
