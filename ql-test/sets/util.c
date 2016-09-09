#include "util.h"

int create_unix_server(char *sk_path)
{
	int server_sk, server_len;
	struct sockaddr_un server_addr, client_addr;

	unlink(sk_path);
	server_sk = socket(AF_UNIX, SOCK_STREAM, 0);
	if (server_sk == -1)
		exit(0);
	server_addr.sun_family = AF_UNIX;
	strcpy(server_addr.sun_path, sk_path);
	server_len = sizeof(server_addr);

	bind(server_sk, (struct sockaddr *) &server_addr, server_len);
	listen(server_sk, 10);
	return server_sk;
}

int connect_to_unix(char *sk_path)
{
	struct sockaddr_un addr;
	int sk = socket(AF_UNIX, SOCK_STREAM, 0), len;
	if (sk < 0)
		return -1;
	bzero(&addr, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, sk_path);
	len = sizeof(addr);
	if (connect(sk, (struct sockaddr *) &addr, len) < 0)
		return -1;
	return sk;
}

int connect_to_remote(char *str_addr, int port)
{
	struct sockaddr_in client_addr;
	struct sockaddr_in server_addr;
	int sk;
	bzero(&client_addr, sizeof(client_addr));
	client_addr.sin_family = AF_INET;
	client_addr.sin_addr.s_addr = htons(INADDR_ANY);
	client_addr.sin_port = htons(0);
	sk = socket(AF_INET, SOCK_STREAM, 0);
	if (sk < 0)
		return -1;
	if (bind(sk, (struct sockaddr *) &client_addr, sizeof(client_addr)))
		return -1;
	bzero(&server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	if (inet_aton(str_addr, &server_addr.sin_addr)==0)
		return -1;

	server_addr.sin_port = htons(port);
	socklen_t length = sizeof(server_addr);
	if (connect(sk, (struct sockaddr *) &server_addr, length)<0)
		return -1;
	return sk;
}

int create_inet_server(int port)
{
	struct sockaddr_in server_addr;
	bzero(&server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htons(INADDR_ANY);
	server_addr.sin_port = htons(port);

	int sk = socket(PF_INET, SOCK_STREAM, 0);
	if (sk < 0)
		return -1;
	{
		int opt = 1;
		setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	}

	if (bind(sk, (struct sockaddr *) &server_addr, sizeof(server_addr)))
		return -1;

	if (listen(sk, 10))
		return -1;
	
	return sk;
}
