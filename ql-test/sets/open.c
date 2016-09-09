#include <stdio.h>
#include <unistd.h>

int main()
{
	FILE* f=fopen("/root/test.log","rw");
	fseek(f,2,SEEK_CUR);
	f=fopen("/root/1","rw+");
	fprintf(f,"www");
	while(1)sleep(1);
	return 0;
}
