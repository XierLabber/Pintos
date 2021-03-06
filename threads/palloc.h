#ifndef THREADS_PALLOC_H
#define THREADS_PALLOC_H

#include <stddef.h>
#include "lib/stdbool.h"
#include "lib/stdint.h"

/** How to allocate pages. */
enum palloc_flags
  {
    PAL_ASSERT = 001,           /**< Panic on failure. */
    PAL_ZERO = 002,             /**< Zero page contents. */
    PAL_USER = 004              /**< User page. */
  };

void palloc_init (size_t user_page_limit);
void *palloc_get_page (enum palloc_flags);
void *palloc_get_multiple (enum palloc_flags, size_t page_cnt);
void palloc_free_page (void *);
void palloc_free_multiple (void *, size_t page_cnt);
bool my_evict(void);
uint32_t* my_choose_evict(uint32_t** upage);

#endif /**< threads/palloc.h */
