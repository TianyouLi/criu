#ifndef __CR_QUICKLAKE_H
#define __CR_QUICKLAKE_H

#define QL_DUMP		38144
#define QL_RESTORE	38145

#define ql_sym(pblob, name) ((void *) (pblob) + quicklake_blob_offset__##name)

extern int switch_ql_state(pid_t pid, int request);
extern int restore_ql_task();

#endif
