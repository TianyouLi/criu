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

#define NR_THREADS	1
#define PORT	1954

int run_child_client(void *arg)
{
	int tid = syscall(__NR_gettid);
	int sk = connect_to_remote("127.0.0.1", PORT);
	if (sk < 0)
		return 0;
	int num = 0;
	do {
		int len = recv(sk, &num, sizeof(num), 0);
		int ret = send(sk, &num, sizeof(num), 0);
		ptf("%d: recv %d send %d ret(%d:%s)\n", tid, num, num, ret, strerror(errno));
	} while (num);
	return 0;
}

int run_child_server(void *arg)
{
	int num;
	int tid = syscall(__NR_gettid);
	int sk = *(int *)arg;

	srand(time(0));
	do {
		num = rand() + 1;
		int ret = send(sk, &num, sizeof(num), 0);
		recv(sk, &num, sizeof(num), 0);
		ptf("%d: send %d recv %d ret(%d:%s)\n", tid, num, num, ret, strerror(errno));
		sleep(10);
	} while (num);
	return 0;
}

int main()
{
	int server_sk = create_inet_server(PORT);
	int nr_child = 4;

	while (nr_child--) {
		struct sockaddr_in client_addr;
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
