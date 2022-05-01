#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "malloc.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/** Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b
#define MY_MLFQS_LENGTH (PRI_MAX - PRI_MIN + 2)

/** List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;
static struct list my_mlfqs_ready_lists[MY_MLFQS_LENGTH];

/** List of all processes.  Processes are added to this list
   when they are first scheduled and removed when they exit. */
static struct list all_list;

static struct list my_sleeping_list;

/** Idle thread. */
static struct thread *idle_thread;

/** Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/** Lock used by allocate_tid(). */
static struct lock tid_lock;

/** Stack frame for kernel_thread(). */
struct kernel_thread_frame 
  {
    void *eip;                  /**< Return address. */
    thread_func *function;      /**< Function to call. */
    void *aux;                  /**< Auxiliary data for function. */
  };

/** Statistics. */
static long long idle_ticks;    /**< # of timer ticks spent idle. */
static long long kernel_ticks;  /**< # of timer ticks in kernel threads. */
static long long user_ticks;    /**< # of timer ticks in user programs. */

/** Scheduling. */
#define TIME_SLICE 4            /**< # of timer ticks to give each thread. */
static unsigned thread_ticks;   /**< # of timer ticks since last yield. */

/** If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *running_thread (void);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static bool is_thread (struct thread *) UNUSED;
static void *alloc_frame (struct thread *, size_t size);
static void schedule (void);
void thread_schedule_tail (struct thread *prev);
static tid_t allocate_tid (void);

/** Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) 
{
  ASSERT (intr_get_level () == INTR_OFF);

  
  enum intr_level old_level = intr_disable ();
  lock_init (&tid_lock);
  lock_init (&my_files_thread_lock);
  list_init (&all_list);
  list_init (&my_sleeping_list);
  list_init (&(my_exec_files));
  #ifdef USERPROG
  list_init (&my_frame_table);
  lock_init(&my_frame_table_lock);
  list_init(&my_sup_table);
  lock_init(&my_sup_table_lock);
  lock_init(&my_evict_lock);
  #endif
  if(thread_mlfqs)
  {

    for(int i = 0; i < MY_MLFQS_LENGTH;i++)
    {
      list_init(&my_mlfqs_ready_lists[i]);
    }
  }
  else
  {
    list_init (&ready_list);
  }
  if(thread_mlfqs)
  {
    my_mlfqs_load_avg = INT_TO_FP(0);
  }
  intr_set_level (old_level);

  /* Set up a thread structure for the running thread. */
  initial_thread = running_thread ();
  init_thread (initial_thread, "main", PRI_DEFAULT);
  
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid ();
}

/** Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) 
{
  /* Create the idle thread. */
  struct semaphore idle_started;
  sema_init (&idle_started, 0);
  thread_create ("idle", PRI_MIN, idle, &idle_started);

  /* Start preemptive thread scheduling. */
  intr_enable ();

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down (&idle_started);
}

/** Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) 
{
  struct thread *t = thread_current ();

  /* Update statistics. */
  if (t == idle_thread)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pagedir != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;

  /* Enforce preemption. */
  if (++thread_ticks >= TIME_SLICE)
    intr_yield_on_return ();
}

/** Prints thread statistics. */
void
thread_print_stats (void) 
{
  printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
          idle_ticks, kernel_ticks, user_ticks);
}

/** Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
               thread_func *function, void *aux) 
{
  struct thread *t;
  struct kernel_thread_frame *kf;
  struct switch_entry_frame *ef;
  struct switch_threads_frame *sf;
  tid_t tid;

  ASSERT (function != NULL);

  /* Allocate thread. */
  t = palloc_get_page (PAL_ZERO);
  if (t == NULL)
    return TID_ERROR;

  /* Initialize thread. */
  init_thread (t, name, priority);
  tid = t->tid = allocate_tid ();
  struct thread* cur_thread = thread_current();
  t->my_mlfqs_nice = cur_thread->my_mlfqs_nice;
  t->my_mlfqs_recent_cpu = cur_thread->my_mlfqs_recent_cpu;

  /* Stack frame for kernel_thread(). */
  kf = alloc_frame (t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function;
  kf->aux = aux;

  /* Stack frame for switch_entry(). */
  ef = alloc_frame (t, sizeof *ef);
  ef->eip = (void (*) (void)) kernel_thread;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame (t, sizeof *sf);
  sf->eip = switch_entry;
  sf->ebp = 0;

#ifdef USERPROG
  if(my_init_finish_flag)
    my_insert_son_thread(thread_current(),t,t->tid);
#endif

  /* Add to run queue. */
  thread_unblock (t);
  
  if(thread_get_priority()<priority)
  {
    thread_yield();
  }

  return tid;
}

/** Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) 
{
  ASSERT (!intr_context ());
  ASSERT (intr_get_level () == INTR_OFF);

  thread_current ()->status = THREAD_BLOCKED;
  schedule ();
}

/** Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) 
{
  enum intr_level old_level;

  ASSERT (is_thread (t));

  old_level = intr_disable ();
  ASSERT (t->status == THREAD_BLOCKED);
  my_insert_ready_thread(&(t->elem));
  t->status = THREAD_READY;
  intr_set_level (old_level);
}

/** Returns the name of the running thread. */
const char *
thread_name (void) 
{
  return thread_current ()->name;
}

/** Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) 
{
  struct thread *t = running_thread ();
  
  /* Make sure T is really a thread.
     If either of these assertions fire, then your thread may
     have overflowed its stack.  Each thread has less than 4 kB
     of stack, so a few big automatic arrays or moderate
     recursion can cause stack overflow. */
  ASSERT (is_thread (t));
  ASSERT (t->status == THREAD_RUNNING);

  return t;
}

/** Returns the running thread's tid. */
tid_t
thread_tid (void) 
{
  return thread_current ()->tid;
}

void my_release_resource(struct thread* t)
{
  struct list_elem *e;

  for (e = list_begin (&t->my_holding_locks_and_priority);
       e != list_end (&t->my_holding_locks_and_priority);
       e = list_next (e))
    {
      struct lock *my_lk = list_entry 
        (e, struct my_locks_and_priorities_list_elem, my_elem)
        ->my_lock;
      lock_release(my_lk);
    }

  while(!list_empty(&t->my_files_list))
    {
      e = list_pop_front(&t->my_files_list);
      struct my_files* the_mf = 
        list_entry(e, struct my_files, elem);
      struct file* the_file = the_mf->f;
      lock_acquire(&my_files_thread_lock);
      file_close(the_file);
      lock_release(&my_files_thread_lock);
      free(the_mf);
    }
    
#ifdef USERPROG
  lock_acquire(&t->my_sons_list_lock);
  while(!list_empty(&t->my_sons_list))
  {
    e = list_pop_front(&t->my_sons_list);
    struct my_son_thread* mst = 
      list_entry(e, struct my_son_thread, elem);
    if(mst->son_ptr != NULL)
    {
      mst->son_ptr->my_parent = NULL;
    }
    free(mst);
  }
  lock_release(&t->my_sons_list_lock);
#endif
}

/** Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) 
{
  ASSERT (!intr_context ());

#ifdef USERPROG
  process_exit ();
#endif

  struct thread * cur_thread=thread_current();
  my_release_resource(cur_thread);

  printf("%s: exit(%d)\n",
        cur_thread->name,cur_thread->my_exit_status);
  #ifdef USERPROG
  if(strcmp(cur_thread->name, "main")!=0)
  {
    struct my_son_thread* mst = 
      my_get_son(cur_thread->tid, cur_thread->my_parent);
    if(mst!=NULL)
    {
      mst->son_ptr = NULL;
      sema_up(&mst->exec_sema);
    }
    sema_up(cur_thread->parent_wait_sema);
  }
  #endif


  /* Remove thread from all threads list, set our status to dying,
     and schedule another process.  That process will destroy us
     when it calls thread_schedule_tail(). */
  intr_disable ();
  list_remove (&cur_thread->allelem);
  thread_current ()->status = THREAD_DYING;
  schedule ();
  NOT_REACHED ();
}

/** Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) 
{
  struct thread *cur = thread_current ();
  enum intr_level old_level;
  
  ASSERT (!intr_context ());

  old_level = intr_disable ();
  if (cur != idle_thread) 
    my_insert_ready_thread(&(cur->elem));
  cur->status = THREAD_READY;
  schedule ();
  intr_set_level (old_level);
}

/** Invoke function 'func' on all threads, passing along 'aux'.
   This function must be called with interrupts off. */
void
thread_foreach (thread_action_func *func, void *aux)
{
  struct list_elem *e;

  ASSERT (intr_get_level () == INTR_OFF);

  for (e = list_begin (&all_list); e != list_end (&all_list);
       e = list_next (e))
    {
      struct thread *t = list_entry (e, struct thread, allelem);
      func (t, aux);
    }
}

/** Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority) 
{
  if(thread_mlfqs)
  {
    return;
  }
  struct thread* my_current_thread= thread_current ();
  enum intr_level old_level = intr_disable ();
  if(list_empty(&(my_current_thread->my_holding_locks_and_priority)))
  {
    bool my_flag=((my_current_thread->priority)>new_priority);
    my_current_thread->priority = new_priority;
    my_current_thread->my_priority_for_sure=new_priority;
    intr_set_level (old_level);
    if(my_flag)
    {
      thread_yield();
    }
  }
  else
  {
    my_current_thread->my_priority_for_sure=new_priority;
    if(my_current_thread->priority < new_priority)
    {
      my_current_thread->priority=new_priority;
    }
    intr_set_level (old_level);
  }
}

/** Returns the current thread's priority. */
int
thread_get_priority (void) 
{
  enum intr_level old_level = intr_disable ();
  int ans = thread_current ()->priority;
  intr_set_level (old_level);
  return ans;
}

/** Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice) 
{
  struct thread *cur_thread = thread_current();
  cur_thread->my_mlfqs_nice=nice;
  my_mlfqs_cal_priority(cur_thread->my_mlfqs_recent_cpu,
                        nice);
}

/** Returns the current thread's nice value. */
int
thread_get_nice (void) 
{
  /* Not yet implemented. */
  return thread_current()->my_mlfqs_nice;
}

/** Returns 100 times the system load average. */
int
thread_get_load_avg (void) 
{
  /* Not yet implemented. */
  enum intr_level old_level = intr_disable ();
  int ans = FP_TO_INT_TO_NEAREST(
    FP_MUL_INT(my_mlfqs_load_avg, 100));
  intr_set_level (old_level);
  return ans;
}

/** Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) 
{
  /* Not yet implemented. */
  return FP_TO_INT_TO_NEAREST(
    FP_MUL_INT(thread_current()->my_mlfqs_recent_cpu,100));
}

/** Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) 
{
  struct semaphore *idle_started = idle_started_;
  idle_thread = thread_current ();
  sema_up (idle_started);

  for (;;) 
    {
      /* Let someone else run. */
      intr_disable ();
      thread_block ();

      /* Re-enable interrupts and wait for the next one.

         The `sti' instruction disables interrupts until the
         completion of the next instruction, so these two
         instructions are executed atomically.  This atomicity is
         important; otherwise, an interrupt could be handled
         between re-enabling interrupts and waiting for the next
         one to occur, wasting as much as one clock tick worth of
         time.

         See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
         7.11.1 "HLT Instruction". */
      asm volatile ("sti; hlt" : : : "memory");
    }
}

/** Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) 
{
  ASSERT (function != NULL);

  intr_enable ();       /**< The scheduler runs with interrupts off. */
  function (aux);       /**< Execute the thread function. */
  thread_exit ();       /**< If function() returns, kill the thread. */
}

/** Returns the running thread. */
struct thread *
running_thread (void) 
{
  uint32_t *esp;

  /* Copy the CPU's stack pointer into `esp', and then round that
     down to the start of a page.  Because `struct thread' is
     always at the beginning of a page and the stack pointer is
     somewhere in the middle, this locates the curent thread. */
  asm ("mov %%esp, %0" : "=g" (esp));
  return pg_round_down (esp);
}

/** Returns true if T appears to point to a valid thread. */
static bool
is_thread (struct thread *t)
{
  return t != NULL && t->magic == THREAD_MAGIC;
}

/** Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority)
{
  enum intr_level old_level;

  ASSERT (t != NULL);
  ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT (name != NULL);

  memset (t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
  strlcpy (t->name, name, sizeof t->name);
  t->stack = (uint8_t *) t + PGSIZE;
  if(thread_mlfqs)
  {
    t->my_mlfqs_nice = 0;
    t->my_mlfqs_recent_cpu = INT_TO_FP(0);
    t->priority = my_mlfqs_cal_priority(
      t->my_mlfqs_recent_cpu, t->my_mlfqs_nice);
    t->my_priority_for_sure = 
      t->priority;
  }
  else
  {
    t->priority = priority;
    t->my_priority_for_sure = priority;
  }
  list_init(&(t->my_holding_locks_and_priority));
  list_init(&(t->my_files_list));
#ifdef USERPROG
  list_init(&(t->my_sons_list));
  lock_init(&(t->my_sons_list_lock));
#endif
  lock_init(&t->my_stack_frame_num_lock);
  t->my_stack_frame_num = 0;
  t->my_waiting_lock=NULL;
  t->magic = THREAD_MAGIC;

  old_level = intr_disable ();
  my_insert_all_thread(&(t->allelem));
  intr_set_level (old_level);
}

/** Allocates a SIZE-byte frame at the top of thread T's stack and
   returns a pointer to the frame's base. */
static void *
alloc_frame (struct thread *t, size_t size) 
{
  /* Stack data is always allocated in word-size units. */
  ASSERT (is_thread (t));
  ASSERT (size % sizeof (uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}

/** Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) 
{
  if(!thread_mlfqs)
  {
    if (list_empty (&ready_list))
      return idle_thread;
    else
      return list_entry (
        list_pop_front (&ready_list), 
        struct thread, 
        elem);
  }
  else
  {
    for(int i = MY_MLFQS_LENGTH - 1; i >= 0 ;i--)
    {
      if(!list_empty(&my_mlfqs_ready_lists[i]))
      {
        return list_entry (
          list_pop_front (&my_mlfqs_ready_lists[i]), 
          struct thread, 
          elem);
      }
    }
    return idle_thread;
  }
}

/** Completes a thread switch by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.  This function is normally invoked by
   thread_schedule() as its final action before returning, but
   the first time a thread is scheduled it is called by
   switch_entry() (see switch.S).

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function.

   After this function and its caller returns, the thread switch
   is complete. */
void
thread_schedule_tail (struct thread *prev)
{
  struct thread *cur = running_thread ();
  
  ASSERT (intr_get_level () == INTR_OFF);

  /* Mark us as running. */
  cur->status = THREAD_RUNNING;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate ();
#endif

  /* If the thread we switched from is dying, destroy its struct
     thread.  This must happen late so that thread_exit() doesn't
     pull out the rug under itself.  (We don't free
     initial_thread because its memory was not obtained via
     palloc().) */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread) 
    {
      ASSERT (prev != cur);
      palloc_free_page (prev);
    }
}

/** Schedules a new process.  At entry, interrupts must be off and
   the running process's state must have been changed from
   running to some other state.  This function finds another
   thread to run and switches to it.

   It's not safe to call printf() until thread_schedule_tail()
   has completed. */
static void
schedule (void) 
{

  struct thread *cur = running_thread ();
  struct thread *next = next_thread_to_run ();
  struct thread *prev = NULL;

  ASSERT (intr_get_level () == INTR_OFF);
  ASSERT (cur->status != THREAD_RUNNING);
  ASSERT (is_thread (next));

  if (cur != next)
    prev = switch_threads (cur, next);
  thread_schedule_tail (prev);
}

/** Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) 
{
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire (&tid_lock);
  tid = next_tid++;
  //printf("debug: %d\n", (int)(tid_lock.holder));
  lock_release (&tid_lock);

  return tid;
}

/** Offset of `stack' member within `struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof (struct thread, stack);

bool my_wakeup_time_cmp(const struct list_elem *a, 
                        const struct list_elem *b, 
                        void* unused UNUSED)
{
  return (list_entry(a, struct thread, my_sleeping_elem)->my_time_to_wake_up
         <list_entry(b, struct thread, my_sleeping_elem)->my_time_to_wake_up);
}

void my_insert_sleeping_thread(struct list_elem *sleeping_elem)
{
  list_insert_ordered(&my_sleeping_list,sleeping_elem,my_wakeup_time_cmp,NULL);
}

void my_wake_up_threads(const int64_t current_time)
{
  ASSERT (intr_get_level () == INTR_OFF);

  bool my_flag = false;

  if(list_empty(&my_sleeping_list))
  {
    return;
  }
  struct thread* tmp_thread;
  while(!list_empty(&my_sleeping_list)&&
        (tmp_thread=list_entry(list_front(&my_sleeping_list), 
                              struct thread, my_sleeping_elem))
        ->my_time_to_wake_up <= current_time)
        {
          my_flag = true;
          thread_unblock(tmp_thread);
          list_pop_front(&my_sleeping_list);
        }
  if(my_flag)
    intr_yield_on_return ();
}

bool my_priority_cmp(const struct list_elem *a, 
                     const struct list_elem *b, 
                     void* unused UNUSED)
{
  return (list_entry(a, struct thread, elem)->priority
         >list_entry(b, struct thread, elem)->priority);
}

void my_insert_ready_thread(struct list_elem *elem)
{
  if(thread_mlfqs)
  {
    int cur_pri = 
      list_entry(elem, struct thread, elem)->priority;
    list_insert_ordered(
      &my_mlfqs_ready_lists[cur_pri],elem,my_priority_cmp,NULL);
  }
  else
  {
    list_insert_ordered(&ready_list,elem,my_priority_cmp,NULL);
  }
}

void my_insert_all_thread(struct list_elem *elem)
{
  list_insert_ordered(&all_list,elem,my_priority_cmp,NULL);
}

int my_mlfqs_cal_priority(fp_t recent_cpu_, int nice_)
{
  int ans = FP_TO_INT_TO_NEAREST(
            FP_SUB_INT(INT_SUB_FP_R_FP(PRI_MAX,
                                       FP_DIV_INT(recent_cpu_,4)),
                       2*nice_));
  if(ans<=PRI_MIN)
  {
    return PRI_MIN;
  }
  else if(ans>=PRI_MAX)
  {
    return PRI_MAX;
  }
  return ans;
}

fp_t my_mlfqs_cal_recent_cpu(fp_t load_avg_, 
                             fp_t recent_cpu_, 
                             int nice_)
{
  return FP_ADD_INT(
    FP_MUL(FP_DIV(FP_MUL_INT(load_avg_, 2), 
                  FP_ADD_INT(FP_MUL_INT(load_avg_, 2), 1)), 
           recent_cpu_),
    nice_);
}

fp_t my_mlfqs_cal_load_avg(fp_t load_avg_, int ready_threads_)
{
  return FP_ADD(FP_DIV_INT(FP_MUL_INT(load_avg_, 59), 60), 
                FP_DIV_INT(INT_TO_FP(ready_threads_),60));
}

bool my_is_idle_thread(struct thread* t)
{
  return t == idle_thread;
}

int my_get_ready_list_length(void)
{
  return (int)list_size(&ready_list);
}

int my_mlfqs_get_sum_ready_lists_length(void)
{
  int ans = 0;
  for(int i = 0; i < MY_MLFQS_LENGTH; i++)
  {
    ans += list_size(&my_mlfqs_ready_lists[i]);
  }
  return ans;
}

void my_mlfqs_update_all_priority(void)
{
  struct list_elem* e;
  for (e = list_begin (&all_list); e != list_end (&all_list);
       e = list_next (e))
      {
        struct thread *t = list_entry (e, struct thread, allelem);
        t->priority = 
          my_mlfqs_cal_priority(t->my_mlfqs_recent_cpu, t->my_mlfqs_nice);
        ASSERT(t->priority>=PRI_MIN && t->priority <= PRI_MAX);
        if(t->status == THREAD_READY)
        {
          list_remove(&t->elem);
          list_push_back(&my_mlfqs_ready_lists[t->priority], &t->elem);
        }
      }
  intr_yield_on_return ();
}

void my_mlfqs_update_all_recent_cpu(fp_t load_avg_)
{
  struct list_elem* e;
  for (e = list_begin (&all_list); e != list_end (&all_list);
       e = list_next (e))
      {
        struct thread *t = list_entry (e, struct thread, allelem);
        t->my_mlfqs_recent_cpu = 
          my_mlfqs_cal_recent_cpu(load_avg_, 
                                  t->my_mlfqs_recent_cpu, 
                                  t->my_mlfqs_nice);
      }
}

struct file* my_get_file(int fd, struct thread* t)
{
  struct list_elem *e;

  for (e = list_begin (&t->my_files_list); e != list_end (&t->my_files_list);
       e = list_next (e))
    {
      struct my_files *the_f = list_entry (e, struct my_files, elem);
      if(the_f->fd == fd)
      {
        return the_f->f;
      }
    }
  return NULL;
}

int my_get_next_fd(struct thread* t)
{
  if(list_empty(&t->my_files_list))
  {
    return 3;
  }

  struct list_elem *e;

  for (e = list_begin (&t->my_files_list); e != list_end (&t->my_files_list);
       e = list_next (e))
    {
      struct my_files *f = list_entry (e, struct my_files, elem);
      struct list_elem *ne = list_next(e);
      if(ne == list_end (&t->my_files_list))
      {
        return f->fd+1;
      }
      struct my_files *next_f = list_entry (ne, struct my_files, elem);
      if(next_f->fd > f->fd+1)
      {
        return f->fd+1;
      }
    }
  return -1;
}

bool my_cmp_files(const struct list_elem* e1, 
                  const struct list_elem* e2, 
                  void* aux UNUSED)
{
  struct my_files *f1 = list_entry (e1, struct my_files, elem);
  struct my_files *f2 = list_entry (e2, struct my_files, elem);
  return f1->fd < f2->fd;
}

void my_insert_file_and_fd(struct file* f, 
                   int fd, struct thread* t)
{
  struct my_files *mf=malloc(sizeof(struct my_files));
  mf->f=f;
  mf->fd=fd;
  list_insert_ordered(&t->my_files_list, 
                      &mf->elem, &my_cmp_files, NULL);
}

int my_insert_file(struct file* f, struct thread* t)
{
  int fd=my_get_next_fd(t);
  my_insert_file_and_fd(f,fd,t);
  return fd;
}

void my_remove_file(int fd, struct thread* t)
{
  struct list_elem *e;

  for (e = list_begin (&t->my_files_list); e != list_end (&t->my_files_list);
       e = list_next (e))
    {
      struct my_files *f = list_entry (e, struct my_files, elem);
      if(f->fd == fd)
      {
        list_remove(e);
        free(f);
        return;
      }
    }
  return;
}

#ifdef USERPROG
void my_insert_son_thread(struct thread* parent_t,
                          struct thread* son_t, 
                          int pid)
{
  son_t->my_parent = parent_t;
  struct my_son_thread* mst = 
    malloc(sizeof(struct my_son_thread));
  mst->end_status = -1;
  sema_init(&mst->sema, 0);
  sema_init(&mst->exec_sema, 0);
  son_t->parent_wait_sema = &mst->sema;
  son_t->parent_wait_exec_sema = & mst->exec_sema;
  mst->pid = pid;
  mst->son_ptr = son_t;
  lock_acquire(&parent_t->my_sons_list_lock);
  list_push_back(&parent_t->my_sons_list, 
                 &mst->elem);
  lock_release(&parent_t->my_sons_list_lock);
}

struct my_son_thread* my_get_son(int pid, struct thread* t)
{
  struct list_elem *e;
  lock_acquire(&t->my_sons_list_lock);
  for (e = list_begin (&t->my_sons_list);
       e != list_end (&t->my_sons_list);
       e = list_next (e))
    {
      struct my_son_thread *mst = 
        list_entry (e, struct my_son_thread, elem);
      if(pid == mst->pid)
      {
        lock_release(&t->my_sons_list_lock);
        return mst;
      }
    }
  lock_release(&t->my_sons_list_lock);
  return NULL;
}

struct file* my_get_delete_exec_file(struct thread* t)
{
  struct list_elem* e;
  lock_acquire(&my_files_thread_lock);
  for(e=list_begin(&my_exec_files);
      e!=list_end(&my_exec_files);
      e=list_next(e))
    {
      struct my_exec_file* mef = 
        list_entry(e, struct my_exec_file, elem);
      if(strcmp(mef->file_name, t->name) == 0 &&
        mef->cur_thread == t)
      {
        list_remove(e);
        lock_release(&my_files_thread_lock);
        struct file* ans = mef->the_file;
        free(mef);
        return ans;
      }
    } 
  lock_release(&my_files_thread_lock);
  return NULL;
}

#endif