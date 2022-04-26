#ifndef USERPROG_EXCEPTION_H
#define USERPROG_EXCEPTION_H

#include "userprog/process.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "lib/string.h"
#include "userprog/process.h"

/** Page fault error code bits that describe the cause of the exception.  */
#define PF_P 0x1    /**< 0: not-present page. 1: access rights violation. */
#define PF_W 0x2    /**< 0: read, 1: write. */
#define PF_U 0x4    /**< 0: kernel, 1: user process. */

void exception_init (void);
void exception_print_stats (void);
#ifdef VM
int my_load_file(struct my_sup_table_elem* sup_elem);
#endif

#endif /**< userprog/exception.h */
