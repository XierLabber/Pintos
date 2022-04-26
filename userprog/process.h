#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "devices/timer.h"
#include "lib/kernel/list.h"

struct my_frame_table_elem
{
    void * upage;
    void * kpage;
    struct list_elem elem;
};

struct list my_frame_table;

int my_page_initialized_flag;
int my_tss_initialized_flag;
int my_init_finish_flag;
bool my_insert_frame_table(void *upage, void *kpage);

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /**< userprog/process.h */
