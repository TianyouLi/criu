#ifndef __CR_QUICKLAKE_H
#define __CR_QUICKLAKE_H
#include "parasite.h"
#include "parasite-syscall.h"

#define QL_DUMP		38144
#define QL_RESTORE	38145

#define ql_sym(pblob, name) ((void *) (pblob) + quicklake_blob_offset__##name)

extern int switch_ql_state(pid_t pid, int request);
extern int restore_ql_task();
extern int ql_free_file(struct parasite_ctl *ctl, struct pstree_item *item,
		struct parasite_drain_fd *dfds);

#endif
