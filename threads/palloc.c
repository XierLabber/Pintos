#include "threads/palloc.h"
#include <bitmap.h>
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "threads/loader.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"

#define MY_MAX_TEST_TIME 64

/** Page allocator.  Hands out memory in page-size (or
   page-multiple) chunks.  See malloc.h for an allocator that
   hands out smaller chunks.

   System memory is divided into two "pools" called the kernel
   and user pools.  The user pool is for user (virtual) memory
   pages, the kernel pool for everything else.  The idea here is
   that the kernel needs to have memory for its own operations
   even if user processes are swapping like mad.

   By default, half of system RAM is given to the kernel pool and
   half to the user pool.  That should be huge overkill for the
   kernel pool, but that's just fine for demonstration purposes. */

/** A memory pool. */
struct pool
  {
    struct lock lock;                   /**< Mutual exclusion. */
    struct bitmap *used_map;            /**< Bitmap of free pages. */
    uint8_t *base;                      /**< Base of pool. */
  };

/** Two pools: one for kernel data, one for user pages. */
static struct pool kernel_pool, user_pool;

static void init_pool (struct pool *, void *base, size_t page_cnt,
                       const char *name);
static bool page_from_pool (const struct pool *, void *page);

/** Initializes the page allocator.  At most USER_PAGE_LIMIT
   pages are put into the user pool. */
void
palloc_init (size_t user_page_limit)
{
  /* Free memory starts at 1 MB and runs to the end of RAM. */
  uint8_t *free_start = ptov (1024 * 1024);
  uint8_t *free_end = ptov (init_ram_pages * PGSIZE);
  size_t free_pages = (free_end - free_start) / PGSIZE;
  size_t user_pages = free_pages / 2;
  size_t kernel_pages;
  if (user_pages > user_page_limit)
    user_pages = user_page_limit;
  kernel_pages = free_pages - user_pages;

  /* Give half of memory to kernel, half to user. */
  init_pool (&kernel_pool, free_start, kernel_pages, "kernel pool");
  init_pool (&user_pool, free_start + kernel_pages * PGSIZE,
             user_pages, "user pool");
}

/** Obtains and returns a group of PAGE_CNT contiguous free pages.
   If PAL_USER is set, the pages are obtained from the user pool,
   otherwise from the kernel pool.  If PAL_ZERO is set in FLAGS,
   then the pages are filled with zeros.  If too few pages are
   available, returns a null pointer, unless PAL_ASSERT is set in
   FLAGS, in which case the kernel panics. */
void *
palloc_get_multiple (enum palloc_flags flags, size_t page_cnt)
{
  struct pool *pool = flags & PAL_USER ? &user_pool : &kernel_pool;
  void *pages;
  size_t page_idx;
  int test_time = MY_MAX_TEST_TIME;

  if (page_cnt == 0)
  {
    return NULL;
  }
  while(test_time--)
  {
    lock_acquire (&pool->lock);
    page_idx = bitmap_scan_and_flip (pool->used_map, 0, page_cnt, false);
    lock_release (&pool->lock);
    if(page_idx != BITMAP_ERROR)
    {
      break;
    }
    else
    {
      if(my_evict())
      {
        continue;
      }
      else
      {
        break;
      }
    }
  }
  if (page_idx != BITMAP_ERROR)
    pages = pool->base + PGSIZE * page_idx;
  else
    pages = NULL;

  if (pages != NULL) 
    {
      if (flags & PAL_ZERO)
        memset (pages, 0, PGSIZE * page_cnt);
    }
  else 
    {
      if (flags & PAL_ASSERT)
        PANIC ("palloc_get: out of pages");
    }

  return pages;
}

/** Obtains a single free page and returns its kernel virtual
   address.
   If PAL_USER is set, the page is obtained from the user pool,
   otherwise from the kernel pool.  If PAL_ZERO is set in FLAGS,
   then the page is filled with zeros.  If no pages are
   available, returns a null pointer, unless PAL_ASSERT is set in
   FLAGS, in which case the kernel panics. */
void *
palloc_get_page (enum palloc_flags flags) 
{
  return palloc_get_multiple (flags, 1);
}

/** Frees the PAGE_CNT pages starting at PAGES. */
void
palloc_free_multiple (void *pages, size_t page_cnt) 
{
  struct pool *pool;
  size_t page_idx;

  ASSERT (pg_ofs (pages) == 0);
  if (pages == NULL || page_cnt == 0)
    return;

  if (page_from_pool (&kernel_pool, pages))
    pool = &kernel_pool;
  else if (page_from_pool (&user_pool, pages))
    pool = &user_pool;
  else
    NOT_REACHED ();

  page_idx = pg_no (pages) - pg_no (pool->base);

#ifndef NDEBUG
  memset (pages, 0xcc, PGSIZE * page_cnt);
#endif
  lock_acquire(&my_frame_table_lock);

  ASSERT (bitmap_all (pool->used_map, page_idx, page_cnt));
  bitmap_set_multiple (pool->used_map, page_idx, page_cnt, false);

  for(unsigned i=0;i<page_cnt;i++)
  {
    struct list_elem* e;
    void* upage = NULL;
    struct thread* cur_thread = NULL;
    for(e=list_begin(&my_frame_table);
        e!=list_end(&my_frame_table);
        e=list_next(e))
    {
      struct my_frame_table_elem* frame_elem = 
        list_entry(e, struct my_frame_table_elem, elem);
      if(frame_elem->kpage == (void*)(pages+i*PGSIZE))
      {
        e=list_prev(e);
        upage = frame_elem->upage;
        cur_thread = frame_elem->cur_thread;
        list_remove(&frame_elem->elem);
        lock_release(&my_frame_table_lock);
        free(frame_elem);
        lock_acquire(&my_frame_table_lock);
        break;
      }
      if(upage!=NULL)
      {
        uint32_t hash_no = my_hash((uint32_t) upage);
        lock_acquire(&my_sup_table_lock[hash_no]);
        struct list_elem* e1;
        for(e1=list_begin(&my_sup_table[hash_no]);
            e1!=list_end(&my_sup_table[hash_no]);
            e1=list_next(e1))
          {
            struct my_sup_table_elem* sup_elem = 
              list_entry(e1, struct my_sup_table_elem, elem);
            if(sup_elem->kpage == (void*)(pages+i*PGSIZE) && 
               sup_elem->cur_thread == cur_thread &&
               sup_elem->upage == upage)
            {
              list_remove(e1);
              free(sup_elem);
              break;
            }
          }
        lock_release(&my_sup_table_lock[hash_no]);
      }
    }
  }
  lock_release(&my_frame_table_lock);

}

/** Frees the page at PAGE. */
void
palloc_free_page (void *page) 
{
  palloc_free_multiple (page, 1);
}

/** Initializes pool P as starting at START and ending at END,
   naming it NAME for debugging purposes. */
static void
init_pool (struct pool *p, void *base, size_t page_cnt, const char *name) 
{
  /* We'll put the pool's used_map at its base.
     Calculate the space needed for the bitmap
     and subtract it from the pool's size. */
  size_t bm_pages = DIV_ROUND_UP (bitmap_buf_size (page_cnt), PGSIZE);
  if (bm_pages > page_cnt)
    PANIC ("Not enough memory in %s for bitmap.", name);
  page_cnt -= bm_pages;

  printf ("%zu pages available in %s.\n", page_cnt, name);

  /* Initialize the pool. */
  lock_init (&p->lock);
  p->used_map = bitmap_create_in_buf (page_cnt, base, bm_pages * PGSIZE);
  p->base = base + bm_pages * PGSIZE;
}

/** Returns true if PAGE was allocated from POOL,
   false otherwise. */
static bool
page_from_pool (const struct pool *pool, void *page) 
{
  size_t page_no = pg_no (page);
  size_t start_page = pg_no (pool->base);
  size_t end_page = start_page + bitmap_size (pool->used_map);

  return page_no >= start_page && page_no < end_page;
}

uint32_t* my_choose_evict(uint32_t** upage)
{
  if(list_empty(&my_frame_table))
  {
    return NULL;
  }

  lock_acquire(&my_frame_table_lock);
  struct list_elem* e;
  for(e=list_rbegin(&my_frame_table);
      e!=list_rend(&my_frame_table);
      e=list_prev(e))
      {
        struct my_frame_table_elem* frame_elem = 
          list_entry(e, struct my_frame_table_elem, elem);
        if(is_user_vaddr(frame_elem->upage) && 
           frame_elem->can_be_evict)
        {
          if(pagedir_is_accessed(frame_elem->cur_thread->pagedir,
                                 frame_elem->upage) ||
             pagedir_is_accessed(frame_elem->cur_thread->pagedir,
                                 frame_elem->kpage))
          {
            e=list_next(e);
            pagedir_set_accessed(frame_elem->cur_thread->pagedir,
                                 frame_elem->upage, false);
            pagedir_set_accessed(frame_elem->cur_thread->pagedir,
                                 frame_elem->kpage, false);
            list_remove(&frame_elem->elem);
            list_push_front(&my_frame_table, &frame_elem->elem);
          }
          else
          {
            uint32_t* ans = frame_elem->kpage;
            *upage = frame_elem->upage;
            frame_elem->can_be_evict = 0;
            lock_release(&my_frame_table_lock);
            return ans;
          }
        }
      }
  lock_release(&my_frame_table_lock);
  return NULL;
}

bool my_evict()
{
  lock_acquire(&my_evict_lock);
  uint32_t* upage;
  uint32_t* evict_kpage = my_choose_evict(&upage);
  bool need_to_swap = false;
  bool is_mmapped = false;
  struct thread* mapped_thread;
  uint32_t hash_no = my_hash((uint32_t)upage);
  lock_acquire(&my_sup_table_lock[hash_no]);
  struct list_elem* e;
  block_sector_t swap_plot;

  for(e=list_begin(&my_sup_table[hash_no]);
      e!=list_end(&my_sup_table[hash_no]);
      e=list_next(e))
    {
      struct my_sup_table_elem* sup_elem = 
        list_entry(e,struct my_sup_table_elem, elem);
      if(sup_elem->kpage == evict_kpage)
      {
        uint32_t* pd = sup_elem->cur_thread->pagedir;
        void * upage = sup_elem->upage;
        if(pagedir_is_dirty(pd, upage) || 
           pagedir_is_dirty(pd, sup_elem->kpage))
        {
          need_to_swap = true;
        }
        if(sup_elem->is_mmaped == MY_IS_MMAPED)
        {
          is_mmapped = true;
          mapped_thread = sup_elem->cur_thread;
        }
        pagedir_clear_page(pd, upage);
      }
    }

  if(need_to_swap)
  {
    if(!is_mmapped)
    {
      lock_acquire(&my_swap_table.lock);
      swap_plot = my_get_swap_plot();
      if(swap_plot == MY_NO_PLOT)
      {
        lock_release(&my_swap_table.lock);
        lock_release(&my_sup_table_lock[hash_no]);
        lock_release(&my_evict_lock);
        return false;
      }
      for(int i=0;i<8;i++)
      {
        block_write(my_swap_table.b, swap_plot + i, ((void *)evict_kpage) + i*BLOCK_SECTOR_SIZE);
      }
      lock_release(&my_swap_table.lock);
      for(e=list_begin(&my_sup_table[hash_no]);
          e!=list_end(&my_sup_table[hash_no]);
          e=list_next(e))
        {
          struct my_sup_table_elem* sup_elem = 
            list_entry(e,struct my_sup_table_elem, elem);
          if(sup_elem->kpage == evict_kpage)
          {
            sup_elem->kpage = NULL;
            sup_elem->swap_plot = swap_plot;
          }
        }
    }
    else
    {
      lock_acquire(&mapped_thread->my_mmap_table_lock);
      struct list_elem* e;
      for(e=list_begin(&mapped_thread->my_mmap_table);
          e!=list_end(&mapped_thread->my_mmap_table);
          e=list_next(e))
        {
          struct my_mmap_table_elem* mmap_elem = 
            list_entry(e, struct my_mmap_table_elem, elem);
          if(mmap_elem->kpage == evict_kpage)
          {
            lock_acquire(mmap_elem->file_lock);
            file_seek(mmap_elem->file,mmap_elem->offset);
            file_write(mmap_elem->file, 
                       evict_kpage, 
                       PGSIZE);
            lock_release(mmap_elem->file_lock);
            break;
          }
        }
      lock_release(&mapped_thread->my_mmap_table_lock);
      
      for(e=list_begin(&my_sup_table[hash_no]);
          e!=list_end(&my_sup_table[hash_no]);
          e=list_next(e))
        {
          struct my_sup_table_elem* sup_elem = 
            list_entry(e,struct my_sup_table_elem, elem);
          if(sup_elem->kpage == evict_kpage)
          {
            sup_elem->kpage = NULL;
            sup_elem->swap_plot = MY_NO_PLOT;
          }
        }
    }
  }
  else
  {
    for(e=list_begin(&my_sup_table[hash_no]);
        e!=list_end(&my_sup_table[hash_no]);
        e=list_next(e))
      {
        struct my_sup_table_elem* sup_elem = 
          list_entry(e,struct my_sup_table_elem, elem);
        if(sup_elem->kpage == evict_kpage)
        {
          sup_elem->kpage = NULL;
          sup_elem->swap_plot = MY_NO_PLOT;
        }
      }
  }
  lock_release(&my_sup_table_lock[hash_no]);
  palloc_free_page(evict_kpage);
  lock_release(&my_evict_lock);
  return true;
}