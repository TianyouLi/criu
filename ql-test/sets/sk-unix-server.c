#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include "util.h"

#define sk_path	"/root/prog/tmp/sk-unix"
int main()
{
	int client_len, client_sk;
	struct sockaddr_un client_addr;
	int byte;
	int server_sk = create_unix_server(sk_path);
	if (server_sk < 0)
		return 0;

	client_len = sizeof(client_addr);
	client_sk = accept(server_sk, (struct sockaddr *) &client_addr, (socklen_t *) &client_len);
	do {
		int i1 = read(client_sk, &byte, sizeof(byte));
		int i2 = write(client_sk, &byte, sizeof(byte));
		printf("%d %d %d\n", byte, i1, i2);
	} while (byte);
}
