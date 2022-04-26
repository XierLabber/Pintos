#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "devices/timer.h"
#include "lib/kernel/list.h"
#include "threads/synch.h"

struct my_frame_table_elem
{
    void * upage;
    void * kpage;
    struct list_elem elem;
};

struct list my_frame_table;

struct lock my_frame_table_lock;

struct my_sup_table_elem
{
    void * upage;
    void * kpage;
    struct thread * cur_thread;
    off_t ofs;
    unsigned int read_bytes;
    unsigned int zero_bytes;
    bool writable;
    struct file *file;
    struct list_elem elem;
};

struct list my_sup_table;

struct lock my_sup_table_lock;

int my_page_initialized_flag;
int my_tss_initialized_flag;
int my_init_finish_flag;
bool my_insert_frame_table(void *upage, void *kpage);
bool my_insert_sup_table(struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable);
bool my_insert_sup_table_with_kpage(struct file *file, off_t ofs, 
              uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes, 
              bool writable, uint8_t *kpage);

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
bool install_page (void *upage, void *kpage, bool writable);
void my_delete_sup_elem_free_kpage_no_lock(
   struct my_sup_table_elem* sup_elem);
void my_delete_mul_sup_free_kpage(
   uint8_t *u_start, uint8_t *uend);
void my_delete_mul_sup_free_kpage_by_thread(void);


#endif /**< userprog/process.h */
