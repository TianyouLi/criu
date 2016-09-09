#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

#define PORT	4591

int main(int argc, char *argv[])
{
	int sk = connect_to_remote("127.0.0.1", PORT);
	if (sk < 0)
		exit(0);
	while (1) {
		num = rand() % 50 + 1;
		send(sk, &num, sizeof(num), 0);
		fout = fopen("client.log", "w");
		fprintf(fout, "send %d\n", num);
		fclose(fout);
		if (!num)
			break;
		recv(sk, &num, sizeof(num), 0);
		fout = fopen("client.log", "w");
		fprintf(fout, "recv %d\n", num);
		fclose(fout);
		sleep(1);
	}
	close(sk);
	return 0;
}
