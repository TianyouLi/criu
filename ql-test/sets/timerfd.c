#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/stat.h>

int main(int argc, char *argv[])
{
	int id;
	struct itimerspec t;

	id = timerfd_create(CLOCK_REALTIME, TFD_CLOEXEC);
	if (id < 0)
		return 0;
	t.it_interval.tv_sec = 1;
	t.it_interval.tv_nsec = 5000;
	t.it_value.tv_sec = 1;
	t.it_value.tv_nsec = 5000;
	if (timerfd_settime(id, 0, &t, NULL))
		return 0;
	while (1) {
		uint64_t get;
		if (read(id, &get, sizeof(uint64_t)) == sizeof(uint64_t)) {
			FILE *f = fopen("./tfd.out", "w");
			fprintf(f, "%llu\n", (unsigned long long) get);
			fclose(f);
		}
		else break;
	}
	return 0;
}
