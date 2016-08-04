#ifndef __CR_QUICKLAKE_H
#define __CR_QUICKLAKE_H

#define QL_DUMP		2257	
#define QL_RESTORE	2261

#define ql_sym(pblob, name) ((void *) (pblob) + quicklake_blob_offset__##name)

extern int switch_ql_state(pid_t pid);

#endif
