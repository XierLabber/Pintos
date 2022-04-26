#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "filesys/file.h"

void syscall_init (void);
#ifdef USERPROG
int my_wait_pid(int the_pid);
#endif

#endif /**< userprog/syscall.h */
