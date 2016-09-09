#ifndef UTIL_H
#define UTIL_H
#include <netinet/in.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#define ptf(fmt, args...)	\
		do {				\
			FILE *fout = fopen("log", "a");	\
			fprintf(fout, fmt, ##args);			\
			fclose(fout);						\
		} while (0)

int connect_to_remote(char *str_addr, int port);
int create_inet_server(int port);
int create_unix_server(char *sk_path);
int connect_to_unix(char *sk_path);
	
#endif
