#ifndef __CR_SEIZE_H__
#define __CR_SEIZE_H__

extern int collect_pstree(pid_t pid);
extern void pstree_switch_state(struct pstree_item *root_item, int st);
extern void unseize_task_and_threads(const struct pstree_item *item, int st);

#endif
