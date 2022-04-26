#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <stdint.h>
#include "../kernel/list.h"
//#include <list.h>
#include "filesys/off_t.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/synch.h"

#define FP_SHIFT 16
#define FP_F (1<<FP_SHIFT)
#define INT_TO_FP(n) (n*FP_F)
#define FP_TO_INT_TO_ZERO(x) (x/FP_F)
#define FP_TO_INT_TO_NEAREST(x) ((x>=0)?((x+(FP_F/2))/FP_F):((x-(FP_F/2))/FP_F))
#define FP_ADD(x,y) (x+y)
#define FP_SUB(x,y) (x-y)
#define FP_ADD_INT(x,n) (x+(n*FP_F))
#define FP_SUB_INT(x,n) (x-(n*FP_F))
#define INT_SUB_FP_R_FP(n,x) ((n*FP_F)-x)
#define FP_MUL(x,y) ((((int64_t)x)*y)/FP_F)
#define FP_MUL_INT(x,n) (x*n)
#define FP_DIV(x,y) ((((int64_t)x)*FP_F)/y)
#define INT_DIV_FP(x,y) (x/(((int64_t)y)*FP_F))
#define FP_DIV_INT(x,n) (x/n)

typedef int fp_t;

/** States in a thread's life cycle. */
enum thread_status
  {
    THREAD_RUNNING,     /**< Running thread. */
    THREAD_READY,       /**< Not running but ready to run. */
    THREAD_BLOCKED,     /**< Waiting for an event to trigger. */
    THREAD_DYING        /**< About to be destroyed. */
  };

/** Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /**< Error value for tid_t. */

/** Thread priorities. */
#define PRI_MIN 0                       /**< Lowest priority. */
#define PRI_DEFAULT 31                  /**< Default priority. */
#define PRI_MAX 63                      /**< Highest priority. */

/** A kernel thread or user process.

   Each thread structure is stored in its own 4 kB page.  The
   thread structure itself sits at the very bottom of the page
   (at offset 0).  The rest of the page is reserved for the
   thread's kernel stack, which grows downward from the top of
   the page (at offset 4 kB).  Here's an illustration:

        4 kB +---------------------------------+
             |          kernel stack           |
             |                |                |
             |                |                |
             |                V                |
             |         grows downward          |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             +---------------------------------+
             |              magic              |
             |                :                |
             |                :                |
             |               name              |
             |              status             |
        0 kB +---------------------------------+

   The upshot of this is twofold:

      1. First, `struct thread' must not be allowed to grow too
         big.  If it does, then there will not be enough room for
         the kernel stack.  Our base `struct thread' is only a
         few bytes in size.  It probably should stay well under 1
         kB.

      2. Second, kernel stacks must not be allowed to grow too
         large.  If a stack overflows, it will corrupt the thread
         state.  Thus, kernel functions should not allocate large
         structures or arrays as non-static local variables.  Use
         dynamic allocation with malloc() or palloc_get_page()
         instead.

   The first symptom of either of these problems will probably be
   an assertion failure in thread_current(), which checks that
   the `magic' member of the running thread's `struct thread' is
   set to THREAD_MAGIC.  Stack overflow will normally change this
   value, triggering the assertion. */
/** The `elem' member has a dual purpose.  It can be an element in
   the run queue (thread.c), or it can be an element in a
   semaphore wait list (synch.c).  It can be used these two ways
   only because they are mutually exclusive: only a thread in the
   ready state is on the run queue, whereas only a thread in the
   blocked state is on a semaphore wait list. */

fp_t my_mlfqs_load_avg;

struct lock my_files_thread_lock;
struct list my_exec_files;

struct my_files
{
   struct file* f;
   int fd;
   struct list_elem elem;
};

struct my_son_thread
{
   struct thread* son_ptr;
   int pid;
   int end_status;
   struct semaphore sema;
   struct semaphore exec_sema;
   struct list_elem elem;
};

struct my_exec_file
{
   char file_name[16];
   struct file* the_file;
   struct list_elem elem;
};

struct thread
  {
    /* Owned by thread.c. */
    tid_t tid;                          /**< Thread identifier. */
    enum thread_status status;          /**< Thread state. */
    char name[16];                      /**< Name (for debugging purposes). */
    uint8_t *stack;                     /**< Saved stack pointer. */
    int priority;                       /**< Priority. */
    struct list_elem allelem;           /**< List element for all threads list. */

    /* Shared between thread.c and synch.c. */
    struct list_elem elem;              /**< List element. */

    struct list_elem my_sleeping_elem;
    int64_t my_time_to_wake_up;
    struct list my_holding_locks_and_priority;
    int my_priority_for_sure;
    struct lock* my_waiting_lock;

    int my_mlfqs_nice;
    fp_t my_mlfqs_recent_cpu;

    int my_exit_status;

    struct list my_files_list;         /**< In ascending fd order   */

#ifdef USERPROG
    /* Owned by userprog/process.c. */
    uint32_t *pagedir;                  /**< Page directory. */

    struct thread* my_parent;
    struct list my_sons_list;
    struct lock my_sons_list_lock;
    struct semaphore* parent_wait_sema;
    struct semaphore* parent_wait_exec_sema;
#endif

    /* Owned by thread.c. */
    unsigned magic;                     /**< Detects stack overflow. */
  };

/** If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

/** Performs some operation on thread t, given auxiliary data AUX. */
typedef void thread_action_func (struct thread *t, void *aux);
void thread_foreach (thread_action_func *, void *);

int thread_get_priority (void);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

bool my_wakeup_time_cmp(const struct list_elem *a, 
                        const struct list_elem *b, 
                        void* unused UNUSED);
void my_insert_sleeping_thread(struct list_elem *sleeping_elem);
void my_wake_up_threads(const int64_t current_time);
bool my_priority_cmp(const struct list_elem *a, 
                     const struct list_elem *b, 
                     void* unused UNUSED);
void my_insert_ready_thread(struct list_elem *elem);
void my_insert_all_thread(struct list_elem *elem);

int my_mlfqs_cal_priority(fp_t recent_cpu_, int nice_);
fp_t my_mlfqs_cal_recent_cpu(fp_t load_avg_, 
                             fp_t recent_cpu_, 
                             int nice_);
fp_t my_mlfqs_cal_load_avg(fp_t load_avg_, int ready_threads);

bool my_is_idle_thread(struct thread* t);
int my_get_ready_list_length(void);
int my_mlfqs_get_sum_ready_lists_length(void);
void my_mlfqs_update_all_priority(void);
void my_mlfqs_update_all_recent_cpu(fp_t load_avg_);
void my_release_resource(struct thread* t);
struct file* my_get_file(int fd, struct thread* t);
int my_get_next_fd(struct thread* t);
bool my_cmp_files(const struct list_elem* e1, 
                  const struct list_elem* e2, 
                  void* aux UNUSED);
void my_insert_file_and_fd(struct file* f, 
                   int fd, struct thread* t);
int my_insert_file(struct file* f, struct thread* t);
void my_remove_file(int fd, struct thread* t);

#ifdef USERPROG
void my_insert_son_thread(struct thread* parent_t,
                          struct thread* son_t, 
                          int pid);
struct my_son_thread* my_get_son(int pid, struct thread* t);
struct file* my_get_delete_exec_file(struct thread* t);
#endif

#endif /**< threads/thread.h */
