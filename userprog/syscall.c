#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"
#include "lib/kernel/stdio.h"
#include "filesys/file.h"
#include "threads/synch.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "lib/kernel/list.h"
#include "devices/input.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"

#define MY_TOTAL_SYSCALL_FUNC_NUM 20

typedef void(*my_sys_func)(struct intr_frame *);

my_sys_func my_syscall_functions[MY_TOTAL_SYSCALL_FUNC_NUM];

static void syscall_handler (struct intr_frame *);

void my_filter_buffer(char* the_buffer, 
                      unsigned the_size, 
                      struct intr_frame *);
void my_get_args(struct intr_frame *f, int arg_num, uint32_t* argv);
void my_return(uint32_t x, struct intr_frame *f);
void my_sys_halt(struct intr_frame *f UNUSED);
void my_sys_exit(struct intr_frame *);
void my_sys_exec(struct intr_frame *);
void my_sys_wait(struct intr_frame *);
void my_sys_create(struct intr_frame *);
void my_sys_remove(struct intr_frame *);
void my_sys_open(struct intr_frame *);
void my_sys_filesize(struct intr_frame *);
void my_sys_read(struct intr_frame *);
void my_sys_write(struct intr_frame *);
void my_sys_seek(struct intr_frame *);
void my_sys_tell(struct intr_frame *);
void my_sys_close(struct intr_frame *);
bool my_judge_ptr(const void* p);
void my_ptr_filter(const void* ptr);
void my_sys_mmap(struct intr_frame *);
void my_sys_munmap(struct intr_frame *);
bool my_judge_ptr_in_stack(const void* p, struct intr_frame *f);
bool my_judge_ok_to_mmap(struct file* the_file, void* addr);
bool my_cmp_mappings(const struct list_elem* e1,
                     const struct list_elem* e2,
                     void* aux UNUSED);

void
syscall_init (void) 
{
  my_syscall_functions[SYS_HALT] = 
    &my_sys_halt;
  my_syscall_functions[SYS_EXIT] = 
    &my_sys_exit;
  my_syscall_functions[SYS_EXEC] = 
    &my_sys_exec;
  my_syscall_functions[SYS_WAIT] = 
    &my_sys_wait;
  my_syscall_functions[SYS_CREATE] = 
    &my_sys_create;
  my_syscall_functions[SYS_REMOVE] = 
    &my_sys_remove;
  my_syscall_functions[SYS_OPEN] = 
    &my_sys_open;
  my_syscall_functions[SYS_FILESIZE] = 
    &my_sys_filesize;
  my_syscall_functions[SYS_READ] = 
    &my_sys_read;
  my_syscall_functions[SYS_WRITE] = 
    &my_sys_write;
  my_syscall_functions[SYS_SEEK] = 
    &my_sys_seek;
  my_syscall_functions[SYS_TELL] = 
    &my_sys_tell;
  my_syscall_functions[SYS_CLOSE] = 
    &my_sys_close;
  my_syscall_functions[SYS_MMAP] = 
    &my_sys_mmap;
  my_syscall_functions[SYS_MUNMAP] = 
    &my_sys_munmap;

  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void my_get_args(struct intr_frame *f, int arg_num, uint32_t* argv)
{
  uint32_t* my_esp = (uint32_t*)f->esp;
  my_ptr_filter(my_esp + arg_num);
  for(int i=0;i<arg_num;i++)
  {
    *(argv++)=(uint32_t)*(++my_esp);
  }
  return;
}

void my_return(uint32_t x, struct intr_frame *f)
{
  f->eax = x;
  return;
}

static void
syscall_handler (struct intr_frame *f) 
{
  uint32_t* my_ptr = f->esp;
  my_ptr_filter(my_ptr);

  int my_id=*my_ptr;

  ASSERT(0<=my_id&&my_id<MY_TOTAL_SYSCALL_FUNC_NUM);

  (my_syscall_functions[my_id])(f);
}

void my_sys_halt(struct intr_frame *f UNUSED)
{
  shutdown_power_off();
}

void my_sys_exit(struct intr_frame *f)
{
  int the_status;
  my_get_args(f,1,(uint32_t *)&the_status);
  struct thread* cur_thread = thread_current();
  #ifdef USERPROG
  if(cur_thread->my_parent != NULL)
  {
    struct my_son_thread * mst = 
      my_get_son(cur_thread->tid, cur_thread->my_parent);
    ASSERT(mst != NULL);
    lock_acquire(&cur_thread->my_parent->my_sons_list_lock);
    mst->son_ptr = NULL;
    mst->end_status = the_status;
    lock_release(&cur_thread->my_parent->my_sons_list_lock);
  }
  #endif
  (cur_thread)
    ->my_exit_status=the_status;
  thread_exit();
}

void my_sys_exec(struct intr_frame *f)
{
  char* my_file;
  my_get_args(f,1,(uint32_t *)&my_file);
  my_ptr_filter(my_file);
  uint32_t ans = (uint32_t)process_execute(my_file);
  my_return(ans,f);
  return;
}

void my_sys_wait(struct intr_frame *f)
{
  #ifdef USERPROG
  int the_pid;
  my_get_args(f,1,(uint32_t *)&the_pid);
  my_return(my_wait_pid(the_pid),f);
  return;
  #else
    f->esp = f->esp;
    return;
  #endif
}

#ifdef USERPROG
int my_wait_pid(int the_pid)
{
  struct my_son_thread* the_wait_son = 
    my_get_son(the_pid, thread_current());
  if(the_wait_son == NULL)
  {
    return -1;
  }
  else
  {
    sema_down(&the_wait_son->sema);
    int ans=the_wait_son->end_status;
    struct thread* cur_thread = thread_current();
    lock_acquire(&cur_thread->my_sons_list_lock);
    list_remove(&the_wait_son->elem);
    lock_release(&cur_thread->my_sons_list_lock);
    free(the_wait_son);
    return ans;
  }
}
#endif

void my_sys_create(struct intr_frame *f)
{
  uint32_t the_args[2];
  my_get_args(f,2,the_args);
  char *the_file=(char *)the_args[0];
  unsigned the_size=(unsigned)the_args[1];
  my_ptr_filter(the_file);
  lock_acquire(&my_files_thread_lock);
  bool ans=filesys_create(the_file, the_size);
  lock_release(&my_files_thread_lock);
  my_return((uint32_t)ans,f);
  return;
}

void my_sys_remove(struct intr_frame *f)
{
  char *the_file;
  my_get_args(f,1,(uint32_t *)&the_file);
  my_ptr_filter(the_file);
  lock_acquire(&my_files_thread_lock);
  bool ans=filesys_remove(the_file);
  lock_release(&my_files_thread_lock);
  my_return((uint32_t)ans,f);
  return;
}

void my_sys_open(struct intr_frame *f)
{
  char* file_name;
  my_get_args(f,1,(uint32_t *)(&file_name));
  my_ptr_filter(file_name);
  int flag = lock_held_by_current_thread(&my_files_thread_lock);
  if(!flag)
    lock_acquire(&my_files_thread_lock);
  struct file* the_file = filesys_open(file_name);
  if(!flag)
    lock_release(&my_files_thread_lock);
  if(the_file!=NULL)
  {
    if(!flag)
      lock_acquire(&my_files_thread_lock);
    int fd = my_insert_file(the_file,thread_current());
    if(!flag)
      lock_release(&my_files_thread_lock);
    my_return(fd,f);
    return;
  }
  else
  {
    my_return(-1,f);
    return;
  }
  return;
}

void my_sys_filesize(struct intr_frame *f)
{
  int the_fd;
  my_get_args(f,1,(uint32_t *)&the_fd);
  struct thread *the_thread = 
    thread_current();
  struct file* the_file = my_get_file(the_fd, the_thread);
  lock_acquire(&my_files_thread_lock);
  off_t ans = file_length(the_file);
  lock_release(&my_files_thread_lock);
  my_return((uint32_t)ans, f);
  return;
}

void my_filter_buffer(char* the_buffer, 
                      unsigned the_size,
                      struct intr_frame * f)
{
  if(!my_judge_ptr_in_stack(the_buffer, f))
    my_ptr_filter(the_buffer);
  unsigned start_pg_no = pg_no(the_buffer);
  unsigned end_pg_no = pg_no(the_buffer + the_size);
  for(unsigned i=start_pg_no + 1;i <= end_pg_no;i++)
  {
    if(!my_judge_ptr_in_stack((void *)(i<<PGBITS), f))
      my_ptr_filter((void *)(i<<PGBITS));
  }
}

void my_sys_read(struct intr_frame *f)
{
  int flag = lock_held_by_current_thread(&my_files_thread_lock);
  uint32_t the_args[3];
  my_get_args(f,3,the_args);
  int the_fd = (int)the_args[0];
  char* the_buffer = (char*)the_args[1];
  unsigned the_size = (unsigned)the_args[2];
  
  my_filter_buffer(the_buffer, the_size, f);
  void* upage = (void*)((pg_no(the_buffer))<<PGBITS);
  struct thread* cur_thread = thread_current();
  uint32_t hash_no = my_hash((uint32_t)upage);
  lock_acquire(&my_sup_table_lock[hash_no]);
  struct list_elem* e;
  for(e=list_begin(&my_sup_table[hash_no]);
      e!=list_end(&my_sup_table[hash_no]);
      e=list_next(e))
    {
      struct my_sup_table_elem* sup_elem = 
        list_entry(e, struct my_sup_table_elem, elem);
      if(sup_elem->upage == upage && 
         sup_elem->cur_thread == cur_thread)
      {
        if(sup_elem->writable == false)
        {
          lock_release(&my_sup_table_lock[hash_no]);
          cur_thread->my_exit_status = -1;
          thread_exit();
        }
        else
        {
          break;
        }
      }
    }
  lock_release(&my_sup_table_lock[hash_no]);

  if(the_fd == 0)
  {
    for(unsigned i=0;i<the_size;i++)
    {
      the_buffer[i]=input_getc();
    }
    my_return((uint32_t)the_size,f);
    return;
  }
  else
  {
    *(char *)the_buffer = *(char *)the_buffer;
    for(void *knock = (void *)((uint32_t)pg_round_down(the_buffer) + PGSIZE);
        (uint32_t)knock <= (uint32_t)(the_buffer + the_size - 1);
        knock = (void *)((uint32_t)knock + PGSIZE))
      {
        *(char *)knock = *(char *)knock;
      }
    lock_acquire(&my_frame_table_lock);
    for(e=list_begin(&my_frame_table);
        e!=list_end(&my_frame_table);
        e=list_next(e))
      {
        struct my_frame_table_elem* frame_elem = 
          list_entry(e, struct my_frame_table_elem, elem);
        if(frame_elem->cur_thread == cur_thread &&
           frame_elem->upage >= pg_round_down(the_buffer) &&
           frame_elem->upage <= 
              pg_round_down((void*)(the_buffer + the_size - 1)))
        {
          frame_elem->can_be_evict = 0;
          // be sure that this page is not evicted here
          *(char *)frame_elem->upage
             =*(char *)frame_elem->upage; 
        }
      }
    lock_release(&my_frame_table_lock);

    struct file* the_file=my_get_file(the_fd, 
                         thread_current());
    if(the_file == NULL)
    {
      my_return((uint32_t)(-1),f);
      return;
    }
    if(!flag)
      lock_acquire(&my_files_thread_lock);
    off_t ans = file_read(the_file, the_buffer, (off_t)the_size);
    if(!flag)  
      lock_release(&my_files_thread_lock);
    lock_acquire(&my_frame_table_lock);
    for(e=list_begin(&my_frame_table);
        e!=list_end(&my_frame_table);
        e=list_next(e))
      {
        struct my_frame_table_elem* frame_elem = 
          list_entry(e, struct my_frame_table_elem, elem);
        if(frame_elem->cur_thread == cur_thread &&
           frame_elem->upage >= pg_round_down(the_buffer) &&
           frame_elem->upage <= 
              pg_round_down((void*)(the_buffer + the_size - 1)))
        {
          frame_elem->can_be_evict = 1;
        }
      }
    lock_release(&my_frame_table_lock);
    my_return((uint32_t)ans,f);
    return;
  }
  return;
}

void my_sys_write(struct intr_frame *f)
{
  int flag = lock_held_by_current_thread(&my_files_thread_lock);
  uint32_t the_args[3];
  my_get_args(f,3,the_args);
  
  int the_fd=(int)the_args[0];
  char* the_buffer=(char*)the_args[1];
  unsigned the_size=(unsigned)the_args[2];

  my_filter_buffer(the_buffer, the_size, f);

  if(the_fd==1)
  {
    putbuf((const char *)the_buffer, the_size);
    my_return(the_size,f);
    return;
  }
  else
  {
    struct file* the_file=my_get_file(the_fd, 
                         thread_current());
    if(the_file == NULL)
    {
      my_return((uint32_t)(-1),f);
      return;
    }
    if(!flag)
      lock_acquire(&my_files_thread_lock);
    off_t ans = file_write(the_file, the_buffer, (off_t)the_size);
    if(!flag)  
      lock_release(&my_files_thread_lock);
    my_return((uint32_t)ans, f);
    return;
  }
}

void my_sys_seek(struct intr_frame *f)
{
  uint32_t the_args[2];
  my_get_args(f,2,the_args);
  int the_fd = (int)the_args[0];
  unsigned the_pos = (unsigned)the_args[1];
  struct thread* the_thread = 
    thread_current();
  struct file* the_file = 
    my_get_file(the_fd, the_thread);
  lock_acquire(&my_files_thread_lock);
  file_seek(the_file, (off_t)the_pos);
  lock_release(&my_files_thread_lock);
  return;
}

void my_sys_tell(struct intr_frame *f)
{
  int the_fd;
  my_get_args(f,1,(uint32_t *)&the_fd);
  struct thread* the_thread = 
    thread_current();
  struct file* the_file = 
    my_get_file(the_fd, the_thread);
  lock_acquire(&my_files_thread_lock);
  off_t ans = file_tell(the_file);
  lock_release(&my_files_thread_lock);
  my_return((uint32_t)ans,f);
  return;
}

void my_sys_close(struct intr_frame *f)
{
  int the_fd;
  my_get_args(f,1,(uint32_t *)&the_fd);
  struct thread* the_thread = 
    thread_current();
  struct file* the_file = 
    my_get_file(the_fd, the_thread);
  int flag = lock_held_by_current_thread(&my_files_thread_lock);
  if(!flag)
    lock_acquire(&my_files_thread_lock);
  file_close(the_file);
  my_remove_file(the_fd, the_thread);
  if(!flag)
    lock_release(&my_files_thread_lock);
  return;
}

bool my_judge_ptr(const void* p)
{
  if(!is_user_vaddr(p) || !is_user_vaddr((char *)p+3))
  {
    return false;
  }
  
  struct list_elem* e;
  uint32_t hash_no = my_hash((uint32_t)pg_round_down(p));
  lock_acquire(&my_sup_table_lock[hash_no]);
  for(e=list_begin(&my_sup_table[hash_no]);
      e!=list_end(&my_sup_table[hash_no]);
      e=list_next(e))
      {
         struct my_sup_table_elem* sup_elem = 
            list_entry(e, struct my_sup_table_elem, elem);
          //printf("%0x,%0x,%0x\n",p,sup_elem->upage,sup_elem->upage + sup_elem->read_bytes);
         if(p>=(void *)sup_elem->upage && 
            p<(void*)(sup_elem->upage + 
            sup_elem->read_bytes + sup_elem->zero_bytes) &&
            thread_current() == sup_elem->cur_thread &&
            (void *)(p+3)>=(void *)sup_elem->upage && 
            (void *)(p+3)<(void*)(sup_elem->upage + 
            sup_elem->read_bytes + sup_elem->zero_bytes) &&
            thread_current() == sup_elem->cur_thread)
            {
              lock_release(&my_sup_table_lock[hash_no]);
              return true;
            }
      }
  lock_release(&my_sup_table_lock[hash_no]);

  void* my_tmp = 
    pagedir_get_page(
      thread_current()->pagedir,p);

  if(my_tmp==NULL)
  {
    return false;
  }

  my_tmp = 
    pagedir_get_page(
      thread_current()->pagedir,p+3);
  if(my_tmp==NULL)
  {
    return false;
  }
  
  return true;
}

void my_ptr_filter(const void* ptr)
{
  if(!my_judge_ptr(ptr))
  {
    thread_current()->my_exit_status=-1;
    thread_exit();
  }
  return;
}

bool my_judge_ptr_in_stack(const void* p, struct intr_frame *f)
{
  if (is_user_vaddr(p) && (uint32_t)p >= (uint32_t)f->esp)
  {
    bool ans = false;  
    struct list_elem* e;
    uint32_t hash_no = my_hash((uint32_t)(pg_round_down(p)));
    lock_acquire(&my_sup_table_lock[hash_no]);
    for(e=list_begin(&my_sup_table[hash_no]);
        e!=list_end(&my_sup_table[hash_no]);
        e=list_next(e))
        {
           struct my_sup_table_elem* sup_elem = 
              list_entry(e, struct my_sup_table_elem, elem);
            //printf("%0x,%0x,%0x\n",p,sup_elem->upage,sup_elem->upage + sup_elem->read_bytes);
           if(p>=(void *)sup_elem->upage && 
              p<(void*)(sup_elem->upage + 
              sup_elem->read_bytes + sup_elem->zero_bytes) &&
              thread_current() == sup_elem->cur_thread)
              {
                ans = true;
                break;
              }
        }
    lock_release(&my_sup_table_lock[hash_no]);
    if(ans == false)
    {
      uint8_t *kpage;
      bool success = false;
      void* fault_upage = pg_round_down(p);
      struct thread* cur_thread = thread_current();

      kpage = palloc_get_page (PAL_USER | PAL_ZERO);
      if (kpage != NULL) 
         {
            success = install_page (fault_upage, kpage, true);
            if (success)
            {
               if(!my_insert_sup_table_with_kpage(NULL,0,
                     (void*)fault_upage, PGSIZE
                     ,0,true,kpage, MY_NOT_MMAPED))
                  {
                     palloc_free_page (kpage);
                     return false;
                  }
               lock_acquire(&cur_thread->my_stack_frame_num_lock);
               cur_thread->my_stack_frame_num++;
               lock_release(&cur_thread->my_stack_frame_num_lock);
               pagedir_set_dirty(cur_thread->pagedir, 
                  (void *)fault_upage,true);
            }
            else
            {
              palloc_free_page (kpage);
              return false;
            }
         }
    }
    return true;
  }
  return false;
}

void my_sys_mmap(struct intr_frame * f)
{
  uint32_t the_args[2];
  int the_fd;
  void* the_addr;
  struct file* the_file;
  struct thread* cur_thread = thread_current();
  my_get_args(f, 2, the_args);
  the_fd = (int)the_args[0];
  the_addr = (void *)the_args[1];
  
  if(the_fd == 0 || the_fd == 1)
  {
    my_return((uint32_t)MY_FALSE_MAPID,f);
    return;
  }

  lock_acquire(&my_files_thread_lock);
  the_file = my_get_file(the_fd, cur_thread);
  lock_release(&my_files_thread_lock);

  if(the_file == NULL)
  {
    my_return((uint32_t)MY_FALSE_MAPID,f);
    return;
  }

  if((uint32_t)the_addr < (uint32_t)PHYS_BASE &&
     (uint32_t)the_addr >= (uint32_t)f->esp)
  {
    my_return((uint32_t)MY_FALSE_MAPID,f);
    return;
  }

  //my_ptr_filter(the_addr);
  if(!is_user_vaddr(the_addr) || 
     !is_user_vaddr((char *)(the_addr)+file_length(the_file)))
  {
    thread_exit();
  }
  

  if(!my_judge_ok_to_mmap(the_file, the_addr))
  {
    my_return((uint32_t)MY_FALSE_MAPID,f);
    return;
  }

  the_file = file_reopen(the_file);

  ASSERT(the_file!=NULL);

  int the_file_length = file_length(the_file);
  int need_pg_num = (the_file_length + PGSIZE - 1) / PGSIZE;

  lock_acquire(&cur_thread->my_mmap_table_lock);
  lock_acquire(&my_evict_lock);
  struct lock* file_lock = malloc(sizeof(struct lock));
  ASSERT(file_lock!=NULL);
  lock_init(file_lock);
  void* running_upage = the_addr;
  void* running_kpage;
  int running_file_length = the_file_length;
  int running_ofs = 0;
  int next_map_id = my_get_next_map_id(cur_thread);
  for(int i=0;i<need_pg_num;i++)
  {
    lock_release(&cur_thread->my_mmap_table_lock);
    lock_release(&my_evict_lock);
    running_kpage = palloc_get_page(PAL_USER);
    lock_acquire(&cur_thread->my_mmap_table_lock);
    lock_acquire(&my_evict_lock);
    ASSERT(running_kpage != NULL);
    int valid_bytes = (running_file_length > PGSIZE)?
      PGSIZE:running_file_length;
    bool result = my_insert_sup_table_with_kpage
                              (the_file, running_ofs, 
                               running_upage, valid_bytes,
                               PGSIZE - valid_bytes, true, 
                               running_kpage, MY_IS_MMAPED);
    ASSERT(result);
    struct my_mmap_table_elem* mmap_elem= 
      malloc(sizeof(struct my_mmap_table_elem));
    ASSERT(mmap_elem != NULL);
    mmap_elem->cur_thread = cur_thread;
    mmap_elem->file = the_file;
    mmap_elem->mapid = next_map_id;
    mmap_elem->upage = running_upage;
    mmap_elem->kpage = running_kpage;
    mmap_elem->offset = running_ofs;
    mmap_elem->valid_bytes = valid_bytes;
    mmap_elem->file_lock = file_lock;
    list_insert_ordered(&cur_thread->my_mmap_table,
                        &mmap_elem->elem, my_cmp_mappings,
                        NULL);
    running_upage += PGSIZE;
    running_file_length -= valid_bytes;
    running_ofs += valid_bytes;
  }
  lock_release(&my_evict_lock);
  lock_release(&cur_thread->my_mmap_table_lock);
  my_return((uint32_t)next_map_id,f);
  return;
}

void my_sys_munmap(struct intr_frame * f)
{
  int the_map_id;
  my_get_args(f,1,(uint32_t*)(&the_map_id));
  struct thread* cur_thread = thread_current();
  lock_acquire(&cur_thread->my_mmap_table_lock);
  struct list_elem* e;
  for(e=list_begin(&cur_thread->my_mmap_table);
      e!=list_end(&cur_thread->my_mmap_table);
      e=list_next(e))
    {
      struct my_mmap_table_elem* mmap_elem = 
        list_entry(e, struct my_mmap_table_elem, elem);
      if(mmap_elem->mapid >= the_map_id)
      {
        break;
      }
    }
  my_delete_mmap_file_in_list(e, cur_thread);
  lock_release(&cur_thread->my_mmap_table_lock);
}

bool my_judge_ok_to_mmap(struct file* file, void* addr)
{
  if(file == NULL)
  {
    return false;
  }
  if(addr == 0)
  {
    return false;
  }
  if(file_length(file) == 0)
  {
    return false;
  }
  if((uint32_t)addr % PGSIZE != 0)
  {
    return false;
  }

  struct list_elem* e;
  struct thread* cur_thread = thread_current();

  uint32_t hash_no = my_hash((uint32_t)addr);

  lock_acquire(&my_sup_table_lock[hash_no]);
  for(e=list_begin(&my_sup_table[hash_no]);
      e!=list_end(&my_sup_table[hash_no]);
      e=list_next(e))
    {
      struct my_sup_table_elem* sup_elem = 
        list_entry(e, struct my_sup_table_elem, elem);
      if(sup_elem->cur_thread == cur_thread &&
         sup_elem->upage == addr)
         {
           lock_release(&my_sup_table_lock[hash_no]);
           return false;
         }
    }
  lock_release(&my_sup_table_lock[hash_no]);

  return true;
}

bool my_cmp_mappings(const struct list_elem* e1,
                     const struct list_elem* e2,
                     void* aux UNUSED)
{
  struct my_mmap_table_elem* mmap_elem1 = 
    list_entry(e1, struct my_mmap_table_elem, elem);
  struct my_mmap_table_elem* mmap_elem2 = 
    list_entry(e2, struct my_mmap_table_elem, elem);
  return mmap_elem1->mapid < mmap_elem2->mapid;
}