#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include "util.h"

#define sk_path "/root/prog/tmp/sk-unix"

int main()
{
	int sk = connect_to_unix(sk_path);
	if (sk == -1)
		exit(0);

	do {
		int num = rand() + 1;
		int i1 = write(sk, &num, sizeof(num));
		int i2 = read(sk, &num, sizeof(num));
		printf("%d %d %d\n", num, i1, i2);
		sleep(1);
	} while (1);

}
