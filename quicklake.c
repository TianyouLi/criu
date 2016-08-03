#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include "util.h"
#include "quicklake.h"

int switch_ql_state(pid_t pid)
{
	int fd = open_proc_rw(pid, "crstat");
	
	if (fd < 0)
		return -1;
	if (ioctl(fd, QL_DUMP))
		return -1;
	close(fd);
	return 0;
}
