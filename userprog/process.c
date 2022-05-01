#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "devices/block.h"

#define MY_MAX_FILE_NAME_LENGTH 130
#define MY_MAX_ARG_LENGTH 60
#define MY_MAX_ARGC 120

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/** Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  char my_file_name[MY_MAX_FILE_NAME_LENGTH];
  int my_index=0;
  char tmp;
  while((tmp=file_name[my_index])!='\0' && tmp!=' ')
  {
    my_file_name[my_index++]=tmp;
  }

  my_file_name[my_index]='\0';

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (my_file_name, PRI_DEFAULT, start_process, fn_copy);
  if (tid == TID_ERROR)
    palloc_free_page (fn_copy); 
#ifdef USERPROG
  struct my_son_thread* mst = 
    my_get_son(tid, thread_current());
  if(my_init_finish_flag && mst != NULL)
  {
    sema_down(&mst->exec_sema);
    if(mst->son_ptr == NULL)
    {
      tid=-1;
    }
  }
#endif
  return tid;
}

/** A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;

  char* my_ptr;
  file_name=strtok_r(file_name_," ",&my_ptr);

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);

  char* my_page=(char *)palloc_get_page(0);
  if(my_page == NULL)
  {
    success = false;
  }

  if(success)
  {
    #ifdef USERPROG
    sema_up(thread_current()->parent_wait_exec_sema);
    #endif
    if_.esp = (void *) PHYS_BASE;
    uint32_t argv[MY_MAX_ARGC], argc = 0;
    ASSERT(my_page != NULL);
    char* my_start=my_page;
    char* my_argc_str[MY_MAX_ARGC];
    char* my_tmp;
    my_page+=MY_MAX_ARG_LENGTH;
    my_argc_str[argc]=my_page;
    strlcpy(my_argc_str[argc++],file_name,MY_MAX_ARG_LENGTH);
    while((my_tmp=strtok_r(NULL," ",&my_ptr))!=NULL)
    {
      my_page+=MY_MAX_ARG_LENGTH;
      if((unsigned)my_page - (unsigned)my_start >= PGSIZE)
      {
        success = false;
        break;
      }
      my_argc_str[argc]=my_page;
      strlcpy(my_argc_str[argc++],my_tmp,MY_MAX_ARG_LENGTH);
    }
    if(success)
    {
      for(int i=argc-1;i>=0;i--)
      {
        int length=strlen(my_argc_str[i])+1;
        if_.esp = (void *)((uint32_t)if_.esp - length);
        argv[i]=(uint32_t)if_.esp;
        memcpy(if_.esp, my_argc_str[i], length);
      }

      if_.esp = (void *)((uint32_t)if_.esp -
                        ((uint32_t)if_.esp%4) - 4);

      *(uint32_t *)if_.esp = 0;

      for(int i=argc-1;i>=0;i--)
      {
        if_.esp = (void *)((uint32_t)if_.esp - 4);
        *(uint32_t *)if_.esp = argv[i];
      }

      if_.esp = (void *)((uint32_t)if_.esp - 4);
      *(uint32_t *)if_.esp = (uint32_t)if_.esp+4;

      if_.esp = (void *)((uint32_t)if_.esp - 4);
      *(uint32_t *)if_.esp = (uint32_t)argc;

      if_.esp = (void *)((uint32_t)if_.esp - 4);
      *(uint32_t *)if_.esp = (uint32_t)NULL;
    }

    palloc_free_page((void *)my_start);
  }

  /* If load failed, quit. */
  palloc_free_page (file_name_);
  if (!success) 
  {
  #ifdef USERPROG
    struct thread* cur = thread_current();
    cur->my_exit_status = -1;
  #endif
    thread_exit ();
  }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/** Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{
  return my_wait_pid(child_tid);
}

/** Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  struct file* the_file = my_get_delete_exec_file(cur);

  if(the_file!=NULL)
  {
    lock_acquire(&my_files_thread_lock);
    file_allow_write(the_file);
    file_close(the_file);
    lock_release(&my_files_thread_lock);
  }


  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      lock_acquire(&cur->my_mmap_table_lock);
      my_delete_mmap_table(cur);
      lock_release(&cur->my_mmap_table_lock);
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      my_delete_mul_sup_free_kpage_by_thread();
    }

}

/** Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */

  /* Activate the new address space. */
  if(my_page_initialized_flag != 0)
  {
    pagedir_activate (t->pagedir);;
  }
  

  /* Set thread's kernel stack for use in processing
     interrupts. */
  if(my_tss_initialized_flag != 0)
  {
    tss_update ();
  }
}

/** We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/** ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/** For use with ELF types in printf(). */
#define PE32Wx PRIx32   /**< Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /**< Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /**< Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /**< Print Elf32_Half in hexadecimal. */

/** Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/** Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/** Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /**< Ignore. */
#define PT_LOAD    1            /**< Loadable segment. */
#define PT_DYNAMIC 2            /**< Dynamic linking info. */
#define PT_INTERP  3            /**< Name of dynamic loader. */
#define PT_NOTE    4            /**< Auxiliary info. */
#define PT_SHLIB   5            /**< Reserved. */
#define PT_PHDR    6            /**< Program header table. */
#define PT_STACK   0x6474e551   /**< Stack segment. */

/** Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /**< Executable. */
#define PF_W 2          /**< Writable. */
#define PF_R 4          /**< Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/** Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  ASSERT(my_page_initialized_flag != 0);
  ASSERT(my_tss_initialized_flag != 0);

  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  process_activate ();

  /* Open executable file. */
  lock_acquire(&my_files_thread_lock);
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }
  struct my_exec_file* mef=malloc(sizeof(struct my_exec_file));
  mef->the_file=file;
  mef->cur_thread = t;
  strlcpy(mef->file_name, file_name, 16);
  list_push_back(&my_exec_files, &mef->elem);
  file_deny_write(file);
  

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
if((!success) && file != NULL)
  {
    file_allow_write(file);
  }
  /* We arrive here whether the load is successful or not. */
  lock_release(&my_files_thread_lock);
  return success;
}

/** load() helpers. */

bool install_page (void *upage, void *kpage, bool writable);

/** Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}


// the exist bit will not set to 1
bool my_insert_sup_table(struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable,
              int is_mmaped)
{
  struct my_sup_table_elem *sup_elem = 
    malloc(sizeof(struct my_sup_table_elem));
  if(sup_elem == NULL)
  {
    return false;
  }
  sup_elem->file = file;
  sup_elem->ofs = ofs;
  sup_elem->upage = upage;
  sup_elem->read_bytes = read_bytes;
  sup_elem->zero_bytes = zero_bytes;
  sup_elem->writable = writable;
  sup_elem->cur_thread = thread_current();
  sup_elem->kpage = NULL;
  sup_elem->swap_plot = MY_NO_PLOT;
  sup_elem->exist = 0;
  sup_elem->is_mmaped = is_mmaped;
  lock_acquire(&my_sup_table_lock);
  list_push_back(&my_sup_table, &sup_elem->elem);
  lock_release(&my_sup_table_lock);
  return true;
}

bool my_insert_sup_table_with_kpage(struct file *file, off_t ofs,
             uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes, 
             bool writable, uint8_t *kpage, int is_mmaped)
{
  struct my_sup_table_elem *sup_elem = 
    malloc(sizeof(struct my_sup_table_elem));
  if(sup_elem == NULL)
  {
    return false;
  }
  sup_elem->file = file;
  sup_elem->ofs = ofs;
  sup_elem->upage = upage;
  sup_elem->read_bytes = read_bytes;
  sup_elem->zero_bytes = zero_bytes;
  sup_elem->writable = writable;
  sup_elem->cur_thread = thread_current();
  sup_elem->kpage = kpage;
  sup_elem->swap_plot = MY_NO_PLOT;
  sup_elem->exist = 1;
  sup_elem->is_mmaped = is_mmaped;
  lock_acquire(&my_sup_table_lock);
  list_push_back(&my_sup_table, &sup_elem->elem);
  lock_release(&my_sup_table_lock);
  return true;
}

/** Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  if((read_bytes + zero_bytes) % PGSIZE != 0)
  {
    printf("file: %p, ofs: %d, upage: %p, read_bytes: %d, zero_bytes: %d, writable: %d\n",
    file, ofs, upage, read_bytes, zero_bytes, writable);
  }
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

#ifdef VM
  //return (my_insert_sup_table(file,ofs,upage,read_bytes,
  //                            zero_bytes,writable));
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;
      
      if(!my_insert_sup_table(file,ofs,upage,page_read_bytes,
                              page_zero_bytes,writable, MY_NOT_MMAPED))
        {
          return false;
        }


      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      ofs+=PGSIZE;
      upage += PGSIZE;
    }
    return true;
#else
  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
#endif
}

/** Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
      {
        if(!my_insert_sup_table_with_kpage(NULL,0,
            (void*)(((uint8_t *) PHYS_BASE) - PGSIZE),PGSIZE
            ,0,true,kpage, MY_NOT_MMAPED))
          {
            palloc_free_page (kpage);
            return false;
          }
        struct thread* cur_thread = thread_current();
        lock_acquire(&cur_thread->my_stack_frame_num_lock);
        cur_thread->my_stack_frame_num++;
        lock_release(&cur_thread->my_stack_frame_num_lock);
        pagedir_set_dirty(cur_thread->pagedir, 
          (void *)(((uint8_t *) PHYS_BASE) - PGSIZE),true);
        *esp = PHYS_BASE;
      }
      else
        palloc_free_page (kpage);
    }
  return success;
}

/** Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */ 
bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  int ans1 = (pagedir_get_page (t->pagedir, upage) == NULL);
  ASSERT(ans1);
  int ans2 =  pagedir_set_page (t->pagedir, upage, kpage, writable);
  int ans = (ans1 && ans2);
  if(ans)
  {
    if(!my_insert_frame_table(upage, kpage))
    {
      return false;
    }
  }
  else
  {
    printf("ans1: %d,ans2: %d\n",ans1,ans2);
  }
  return ans;
}
bool my_insert_frame_table(void *upage, void *kpage)
{
  struct my_frame_table_elem *frame_elem = 
    malloc(sizeof(struct my_frame_table_elem));
  if(frame_elem == NULL)
  {
    ASSERT(frame_elem != NULL);
    return false;
  }
  frame_elem->can_be_evict=1;
  frame_elem->kpage=kpage;
  frame_elem->upage=upage;
  frame_elem->cur_thread = thread_current();
  lock_acquire(&my_frame_table_lock);
  list_push_front(&my_frame_table ,&frame_elem->elem);
  lock_release(&my_frame_table_lock);
  return true;
}
void my_delete_sup_elem_free_kpage_no_lock(
   struct my_sup_table_elem* sup_elem)
{
   if(sup_elem->kpage!=NULL)
      palloc_free_page(sup_elem->kpage);
   list_remove(&sup_elem->elem);
   free(sup_elem);
}

void my_delete_mul_sup_free_kpage(
   uint8_t *u_start, uint8_t *u_end)
{
   struct thread* cur_thread=thread_current();
   struct list_elem* e;
   lock_acquire(&my_sup_table_lock);
  for(e=list_begin(&my_sup_table);
      e!=list_end(&my_sup_table);
      e=list_next(e))
      {
         struct my_sup_table_elem* sup_elem = 
            list_entry(e, struct my_sup_table_elem, elem);
         if(sup_elem->cur_thread == cur_thread && 
            sup_elem->upage >= (void *)u_start && 
            sup_elem->upage < (void *)u_end)
            {
               e=list_prev(e);
               my_delete_sup_elem_free_kpage_no_lock(sup_elem);
            }
      }
   lock_release(&my_sup_table_lock);
}

void my_delete_mul_sup_free_kpage_by_thread()
{
   struct thread* cur_thread=thread_current();
   struct list_elem* e;
   lock_acquire(&my_sup_table_lock);
  for(e=list_begin(&my_sup_table);
      e!=list_end(&my_sup_table);
      e=list_next(e))
      {
         struct my_sup_table_elem* sup_elem = 
            list_entry(e, struct my_sup_table_elem, elem);
         if(sup_elem->cur_thread == cur_thread)
            {
               e=list_prev(e);
               my_delete_sup_elem_free_kpage_no_lock(sup_elem);
            }
      }
   lock_release(&my_sup_table_lock);
}

void my_swap_table_init(void)
{
  lock_init(&my_swap_table.lock);
  my_swap_table.b = block_get_role(BLOCK_SWAP);
  int size = my_swap_table.b->size;
  ASSERT(size>0);
  my_swap_table.base = malloc(size+1);
  my_swap_table.used_map = bitmap_create_in_buf(size,my_swap_table.base,size+1);
}

// will not use lock
// return MY_NO_PLOT if failed
block_sector_t my_get_swap_plot(void)
{
  size_t page_idx;
  block_sector_t swap_plot;

  page_idx = bitmap_scan_and_flip
    (my_swap_table.used_map, 0, 8, false);

  if(page_idx != BITMAP_ERROR)
    swap_plot = page_idx;
  else
    swap_plot = MY_NO_PLOT;

  return swap_plot;
}

// will not use lock
int my_get_next_map_id(struct thread * t)
{
  struct list_elem *e;

  if(list_empty(&t->my_mmap_table))
  {
    return 1;
  }

  for (e = list_begin (&t->my_mmap_table); 
       e != list_end (&t->my_mmap_table);
       e = list_next (e))
    {
      struct my_mmap_table_elem *mmap_elem =
       list_entry (e, struct my_mmap_table_elem, elem);
      struct list_elem *ne = list_next(e);
      if(ne == list_end (&t->my_mmap_table))
      {
        return mmap_elem->mapid+1;
      }
      struct my_mmap_table_elem *next_mmap_elem = 
        list_entry (ne, struct my_mmap_table_elem, elem);
      if(next_mmap_elem->mapid > mmap_elem->mapid+1)
      {
        return mmap_elem->mapid+1;
      }
    }
  return -1;
}

// need mmap table lock before called
void my_delete_mmap_file_in_list(struct list_elem* e,
                                 struct thread* cur_thread)
{
  struct my_mmap_table_elem* mmap_elem = 
    list_entry(e, struct my_mmap_table_elem, elem);
  int the_map_id = mmap_elem->mapid;
  struct file* the_file = mmap_elem->file;
  struct lock* the_lock = mmap_elem->file_lock;
  ASSERT(the_lock!=NULL);
  lock_acquire(the_lock);
  for( ;
      e!=list_end(&cur_thread->my_mmap_table);
      e=list_next(e))
    {
      mmap_elem = 
        list_entry(e, struct my_mmap_table_elem, elem);
      if(mmap_elem->mapid > the_map_id)
      {
        break;
      }
      if(mmap_elem->mapid == the_map_id)
      {
        e=list_prev(e);
        if(pagedir_is_dirty(cur_thread->pagedir,
                            mmap_elem->upage))
          {
            file_seek(mmap_elem->file,mmap_elem->offset);
            file_write(mmap_elem->file, 
                       mmap_elem->kpage, 
                       PGSIZE);
          }
        my_delete_mul_sup_free_kpage(mmap_elem->upage, 
                                     mmap_elem->upage+PGSIZE);
        list_remove(&mmap_elem->elem);
        free(mmap_elem);
      }
    }
  file_close(the_file);
  lock_release(the_lock);
  free(the_lock);
}

// need mmap lock before called!
void my_delete_mmap_table(struct thread* cur_thread)
{
  while(!list_empty(&cur_thread->my_mmap_table))
  {
    my_delete_mmap_file_in_list(list_begin(&cur_thread->my_mmap_table),
                                cur_thread);
  }
}