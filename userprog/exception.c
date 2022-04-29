#include "userprog/exception.h"
#include <inttypes.h>
#include <stdio.h>
#include "userprog/gdt.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/block.h"
#include "userprog/pagedir.h"

/** Number of page faults processed. */
static long long page_fault_cnt;

static void kill (struct intr_frame *);
static void page_fault (struct intr_frame *);

/** Registers handlers for interrupts that can be caused by user
   programs.

   In a real Unix-like OS, most of these interrupts would be
   passed along to the user process in the form of signals, as
   described in [SV-386] 3-24 and 3-25, but we don't implement
   signals.  Instead, we'll make them simply kill the user
   process.

   Page faults are an exception.  Here they are treated the same
   way as other exceptions, but this will need to change to
   implement virtual memory.

   Refer to [IA32-v3a] section 5.15 "Exception and Interrupt
   Reference" for a description of each of these exceptions. */
void
exception_init (void) 
{
  /* These exceptions can be raised explicitly by a user program,
     e.g. via the INT, INT3, INTO, and BOUND instructions.  Thus,
     we set DPL==3, meaning that user programs are allowed to
     invoke them via these instructions. */
  intr_register_int (3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
  intr_register_int (4, 3, INTR_ON, kill, "#OF Overflow Exception");
  intr_register_int (5, 3, INTR_ON, kill,
                     "#BR BOUND Range Exceeded Exception");

  /* These exceptions have DPL==0, preventing user processes from
     invoking them via the INT instruction.  They can still be
     caused indirectly, e.g. #DE can be caused by dividing by
     0.  */
  intr_register_int (0, 0, INTR_ON, kill, "#DE Divide Error");
  intr_register_int (1, 0, INTR_ON, kill, "#DB Debug Exception");
  intr_register_int (6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
  intr_register_int (7, 0, INTR_ON, kill,
                     "#NM Device Not Available Exception");
  intr_register_int (11, 0, INTR_ON, kill, "#NP Segment Not Present");
  intr_register_int (12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
  intr_register_int (13, 0, INTR_ON, kill, "#GP General Protection Exception");
  intr_register_int (16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
  intr_register_int (19, 0, INTR_ON, kill,
                     "#XF SIMD Floating-Point Exception");

  /* Most exceptions can be handled with interrupts turned on.
     We need to disable interrupts for page faults because the
     fault address is stored in CR2 and needs to be preserved. */
  intr_register_int (14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}

/** Prints exception statistics. */
void
exception_print_stats (void) 
{
  printf ("Exception: %lld page faults\n", page_fault_cnt);
}

/** Handler for an exception (probably) caused by a user process. */
static void
kill (struct intr_frame *f) 
{
  /* This interrupt is one (probably) caused by a user process.
     For example, the process might have tried to access unmapped
     virtual memory (a page fault).  For now, we simply kill the
     user process.  Later, we'll want to handle page faults in
     the kernel.  Real Unix-like operating systems pass most
     exceptions back to the process via signals, but we don't
     implement them. */
     
  /* The interrupt frame's code segment value tells us where the
     exception originated. */
  switch (f->cs)
    {
    case SEL_UCSEG:
      /* User's code segment, so it's a user exception, as we
         expected.  Kill the user process.  */
      printf ("%s: dying due to interrupt %#04x (%s).\n",
              thread_name (), f->vec_no, intr_name (f->vec_no));
      intr_dump_frame (f);
      thread_exit (); 

    case SEL_KCSEG:
      /* Kernel's code segment, which indicates a kernel bug.
         Kernel code shouldn't throw exceptions.  (Page faults
         may cause kernel exceptions--but they shouldn't arrive
         here.)  Panic the kernel to make the point.  */
      printf("FAULT: %p\n",f->eip);
      intr_dump_frame (f);
      PANIC ("Kernel bug - unexpected interrupt in kernel"); 

    default:
      /* Some other code segment?  Shouldn't happen.  Panic the
         kernel. */
      printf ("Interrupt %#04x (%s) in unknown segment %04x\n",
             f->vec_no, intr_name (f->vec_no), f->cs);
      thread_exit ();
    }
}

#ifdef VM


int my_load_file(struct my_sup_table_elem* sup_elem)
{
   lock_acquire(&my_evict_lock);
   struct file * file = sup_elem->file;
   off_t ofs = sup_elem->ofs;
   uint8_t *upage = sup_elem->upage;
   uint8_t *u_start = sup_elem->upage;
   uint32_t read_bytes = sup_elem->read_bytes; 
   uint32_t zero_bytes = sup_elem->zero_bytes; 
   bool writable = sup_elem->writable;

   printf("LOAD: %p\n",file);

   lock_acquire(&my_sup_table_lock);
   list_remove(&sup_elem->elem);
   lock_release(&my_sup_table_lock);

   free(sup_elem);

   file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      lock_release(&my_evict_lock);
      uint8_t *kpage = palloc_get_page (PAL_USER);
      lock_acquire(&my_evict_lock);
      if (kpage == NULL)
      {
         my_delete_mul_sup_free_kpage(u_start,upage);
         lock_release(&my_evict_lock);
         printf("LOAD FAILED!1\n");
        return false;
      }

      /* Load this page. */
      lock_acquire(&my_files_thread_lock);
      int ans = file_read (file, kpage, page_read_bytes);
      lock_release(&my_files_thread_lock);
      if (ans != (int) page_read_bytes)
        {
          my_delete_mul_sup_free_kpage(u_start,upage);
          palloc_free_page (kpage);
          lock_release(&my_evict_lock);
         printf("LOAD FAILED!2\n");
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          my_delete_mul_sup_free_kpage(u_start,upage);
          palloc_free_page (kpage);
          lock_release(&my_evict_lock);
         printf("LOAD FAILED!3\n");
          return false; 
        }

      lock_release(&my_evict_lock);

      if(!my_insert_sup_table_with_kpage(file, ofs, upage,
                                         read_bytes, zero_bytes,
                                         writable, kpage))
         {
           lock_acquire(&my_evict_lock);
           my_delete_mul_sup_free_kpage(u_start,upage);
           palloc_free_page (kpage);
           lock_release(&my_evict_lock);
         printf("LOAD FAILED!4\n");
           return false; 
         }
           lock_acquire(&my_evict_lock);

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      ofs+=PGSIZE;
      upage += PGSIZE;
    }
    lock_release(&my_evict_lock);
  return true;
}
#endif

/** Page fault handler.  This is a skeleton that must be filled in
   to implement virtual memory.  Some solutions to project 2 may
   also require modifying this code.

   At entry, the address that faulted is in CR2 (Control Register
   2) and information about the fault, formatted as described in
   the PF_* macros in exception.h, is in F's error_code member.  The
   example code here shows how to parse that information.  You
   can find more information about both of these in the
   description of "Interrupt 14--Page Fault Exception (#PF)" in
   [IA32-v3a] section 5.15 "Exception and Interrupt Reference". */
static void
page_fault (struct intr_frame *f) 
{
  bool not_present;  /**< True: not-present page, false: writing r/o page. */
  bool write;        /**< True: access was write, false: access was read. */
  bool user;         /**< True: access by user, false: access by kernel. */
  void *fault_addr;  /**< Fault address. */


  /* Obtain faulting address, the virtual address that was
     accessed to cause the fault.  It may point to code or to
     data.  It is not necessarily the address of the instruction
     that caused the fault (that's f->eip).
     See [IA32-v2a] "MOV--Move to/from Control Registers" and
     [IA32-v3a] 5.15 "Interrupt 14--Page Fault Exception
     (#PF)". */
  asm ("movl %%cr2, %0" : "=r" (fault_addr));

  struct thread* cur_thread = thread_current();

#ifdef VM
   lock_acquire(&my_evict_lock);
  void* fault_upage = pg_round_down(fault_addr);
  int flag = 1;
  int found = 0;
  intr_enable ();
  lock_acquire(&my_sup_table_lock);
  struct list_elem* e;
  for(e=list_begin(&my_sup_table);
      e!=list_end(&my_sup_table);
      e=list_next(e))
      {
         struct my_sup_table_elem* sup_elem = 
            list_entry(e, struct my_sup_table_elem, elem);
         if(sup_elem->kpage == NULL &&
            sup_elem->cur_thread == cur_thread && 
            sup_elem->upage == fault_upage &&
            sup_elem->exist == 0)
            {
               found = 1;
               printf("REACH HERE!1, %p, FILE: %p\n",sup_elem->upage,sup_elem->file);
               lock_release(&my_sup_table_lock);
               lock_release(&my_evict_lock);
               if(!my_load_file(sup_elem))
               {
                  lock_acquire(&my_evict_lock);
                  lock_acquire(&my_sup_table_lock);
                  flag = 0;
                  break;
               }
               else
               {
                  return;
               }
            }
      }
   if(flag)
   {
      for(e=list_begin(&my_sup_table);
         e!=list_end(&my_sup_table);
         e=list_next(e))
         {
            struct my_sup_table_elem* sup_elem = 
               list_entry(e, struct my_sup_table_elem, elem);
            if(sup_elem->upage == fault_upage &&
               sup_elem->cur_thread == cur_thread)
               {
                  found = 1;
                  if(sup_elem->swap_plot == MY_NO_PLOT)
                  {
                     printf("REACH HERE!2, %p\n",sup_elem->upage);
                     list_remove(&sup_elem->elem);
                     lock_release(&my_sup_table_lock);
                     lock_release(&my_evict_lock);
                     bool ans = load_segment(sup_elem->file,
                                             sup_elem->ofs,
                                             sup_elem->upage,
                                             sup_elem->read_bytes,
                                             sup_elem->zero_bytes,
                                             sup_elem->writable);
                     lock_acquire(&my_evict_lock);
                     lock_acquire(&my_sup_table_lock);
                     free(sup_elem);
                     if(!ans)
                     {
                        flag = 0;
                        break;
                     }
                     lock_release(&my_sup_table_lock);
                     lock_release(&my_evict_lock);
                     return;
                  }
                  else
                  {
                     printf("REACH HERE!3, %p\n",sup_elem->upage);
                     lock_release(&my_sup_table_lock);
                     lock_release(&my_evict_lock);
                     uint8_t *kpage = palloc_get_page (PAL_USER);
                     lock_acquire(&my_evict_lock);
                     lock_acquire(&my_sup_table_lock);
                     if(kpage == NULL)
                     {
                        flag = 0;
                        break;
                     }
                     lock_acquire(&my_swap_table.lock);
                     for(int i=0;i<8;i++)
                     {
                        block_read(my_swap_table.b, 
                                 sup_elem->swap_plot + i, 
                                 ((void*)kpage) + i*BLOCK_SECTOR_SIZE);
                     }
                     bitmap_set_multiple(
                        my_swap_table.used_map,
                        sup_elem->swap_plot,
                        8,false);
                     lock_release(&my_swap_table.lock);
                     install_page(sup_elem->upage, 
                                  kpage, 
                                  sup_elem->writable);
                     sup_elem->kpage = kpage;
                     pagedir_set_dirty(sup_elem->cur_thread->pagedir,
                                       sup_elem->upage, true);
                     pagedir_set_accessed(sup_elem->cur_thread->pagedir,
                                         sup_elem->upage, true);
                     lock_release(&my_sup_table_lock);
                     lock_release(&my_evict_lock);
                     return;
                  }
               }
         }
   }
   ASSERT(found == 0);
   lock_release(&my_sup_table_lock);
   lock_release(&my_evict_lock);
   intr_disable();
#endif

  cur_thread->my_exit_status = -1;

  /* Turn interrupts back on (they were only off so that we could
     be assured of reading CR2 before it changed). */
  intr_enable ();
  

  /* Count page faults. */
  page_fault_cnt++;


  /* Determine cause. */
  not_present = (f->error_code & PF_P) == 0;
  write = (f->error_code & PF_W) != 0;
  user = (f->error_code & PF_U) != 0;

  /* To implement virtual memory, delete the rest of the function
     body, and replace it with code that brings in the page to
     which fault_addr refers. */
  printf ("Page fault at %p: %s error %s page in %s context.\n",
          fault_addr,
          not_present ? "not present" : "rights violation",
          write ? "writing" : "reading",
          user ? "user" : "kernel");
  kill (f);
}

