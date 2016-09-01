#ifndef __CR_QUICKLAKE_H
#define __CR_QUICKLAKE_H
#include "parasite.h"
#include "parasite-syscall.h"

enum {
	QL_TASK_STATE_NONE = 1,
	QL_TASK_STATE_DUMP,
	QL_TASK_STATE_RESTORE,
};

#define is_ql_task_none		(quicklake_task_state == QL_TASK_STATE_NONE)
#define is_ql_task_dump		(quicklake_task_state == QL_TASK_STATE_DUMP)
#define is_ql_task_restore	(quicklake_task_state == QL_TASK_STATE_RESTORE)

#define IOC_QL_DUMP		38144
#define IOC_QL_RESTORE	38145

#define ql_sym(pblob, name) ((void *) (pblob) + quicklake_blob_offset__##name)

extern int switch_ql_state(pid_t pid, int request);
extern int restore_ql_task();
extern int quicklake_task_state;

#endif
