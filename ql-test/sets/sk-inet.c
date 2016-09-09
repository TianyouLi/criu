#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#define PORT	4591
int main(int argc, char *argv[])
{
	struct sockaddr_in server_addr;
	bzero(&server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htons(INADDR_ANY);
	server_addr.sin_port = htons(PORT);

	int sk = socket(PF_INET, SOCK_STREAM, 0);
	if (sk < 0)
		exit(1);
	{
		int opt = 1;
		setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	}

	if (bind(sk, (struct sockaddr *) &server_addr, sizeof(server_addr)))
		exit(1);

	if (listen(sk, 10)) {
		exit(1);
	}

	while (1) {
		struct sockaddr_in client_addr;
		socklen_t length = sizeof(client_addr);

		int new_sk = accept(sk, (struct sockaddr *)&client_addr, &length);
		if (new_sk < 0)
			break;
		int num = 0;

		do {
			length = recv(new_sk, &num, sizeof(num), 0);
			int ret = send(new_sk, &num, sizeof(num), 0);
			FILE* fout = fopen("inet.log", "w");
			fprintf(fout, "%d recv: %d %d %s\n", new_sk, num, ret, strerror(errno));
			fclose(fout);
		} while (++num);
		close(new_sk);
	}

	close(sk);
	return 0;
}
