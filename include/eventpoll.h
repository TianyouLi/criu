#ifndef __CR_EVENTPOLL_H__
#define __CR_EVENTPOLL_H__

#include "files.h"

struct epoll_arg {
	int epoll_fd;
	int nr_fd;
	struct {
		int fd;
		int event;
		long long event_data;
	} p[0];
};

extern int is_eventpoll_link(char *link);
extern const struct fdtype_ops eventpoll_dump_ops;
extern struct collect_image_info epoll_tfd_cinfo;
extern struct collect_image_info epoll_cinfo;
extern int eventpoll_count_tfds(struct file_desc *d);
extern void eventpoll_collect_args(struct file_desc *d, struct epoll_arg *arg);

#define parasite_epoll_size(n)	(sizeof(struct epoll_arg) +	\
		sizeof(((struct epoll_arg *)NULL)->p[0]) * n)

#endif /* __CR_EVENTPOLL_H__ */
