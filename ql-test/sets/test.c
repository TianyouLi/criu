#include <sys/inotify.h>
#include <unistd.h>
#include <stdio.h>


struct a {
	int b;
	struct {
		int b;
	} bs[0];
};

int main()
{
	struct a *ptr = NULL;
	printf("%d\n", sizeof(struct a));
	printf("%d\n", sizeof(ptr->bs[0]));
}
