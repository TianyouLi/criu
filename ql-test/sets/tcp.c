#include <sys/socket.h>
#include <stdio.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define GK_PORT		1954
#define SEND_LEN	1024000000
int server()
{
	struct sockaddr_in server_addr, client_addr;
	int sk;
	unsigned long sum = 0;

	bzero(&server_addr, sizeof(struct sockaddr_in));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htons(INADDR_ANY);
	server_addr.sin_port = htons(GK_PORT);
	
	sk = socket(PF_INET, SOCK_STREAM, 0);
	if (sk < 0) {
		printf("Fail to create server\n");
		return 0;
	}

	if (bind(sk, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1) {
		printf("Fail to bind\n");
		return 0;
	}

	if (listen(sk, 1) == -1) {
		printf("Fail to listen\n");
		return 0;
	}

	{
		int client, len;
		unsigned char buf;
		int count = 0;
		socklen_t addr_len = sizeof(struct sockaddr_in);
		if ((client = accept(sk, (struct sockaddr *)&client_addr, &addr_len)) == -1) {
			printf("Fail to accept\n");
			return 0;
		}
		while ((len = recv(client, &buf, 1, 0)) > 0) {
			sum += buf;
			if (++count % 10240 == 0)
				printf("Recv: %llu\n", sum);
		}
		close(client);
		printf("Receive %llu\n", sum);
		sum = 0;
	}
	return 0;
}

void client()
{
	struct sockaddr_in client_addr, server_addr;
	int sk, i;
	socklen_t addr_len;
	unsigned long sum;

	bzero(&client_addr, sizeof(client_addr));
	client_addr.sin_family = AF_INET;
	client_addr.sin_addr.s_addr = htons(INADDR_ANY);
	client_addr.sin_port = htons(0);
	sk = socket(AF_INET, SOCK_STREAM, 0);
	if (sk < 0) {
		printf("Client: Fail socket\n");
		return;
	}
	if (bind(sk, (struct sockaddr *)&client_addr, sizeof(client_addr))) {
		printf("Client: Fail bind\n");
		return;
	}
	bzero(&server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	if (inet_aton("127.0.0.1", &server_addr.sin_addr) == 0) {
		printf("Client: Fail IP\n");
		return;
	}
	server_addr.sin_port = htons(GK_PORT);
	addr_len = sizeof(server_addr);
	if (connect(sk, (struct sockaddr *)&server_addr, addr_len) < 0) {
		printf("Client: Fail connect\n");
		return;
	}
	i = 0;
	while (i++ < SEND_LEN) {
		unsigned char ch = rand() % 256;
		sum += ch;
		if (i % 10240 == 0)
			printf("Send: %llu\n", sum);
		send(sk, &ch, 1, 0);
	}
	printf("Send:%llu\n", sum);
	close(sk);
}

int main()
{
	int pid;

	pid = fork();

	if (pid < 0) {
		printf("Fail to fork\n");
		return 0;
	} else if (pid) {
		server();
		waitpid(pid, NULL, 0);
	} else {
		client();
		return 0;
	}
}
