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
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* Random value for basic thread
   Do not modify this value. */
#define THREAD_BASIC 0xd42df210

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Thread destruction requests */
static struct list destruction_req;

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static void do_schedule(int status);
static void schedule (void);
static tid_t allocate_tid (void);

/* Returns true if T appears to point to a valid thread. */
#define is_thread(t) ((t) != NULL && (t)->magic == THREAD_MAGIC)

/* Returns the running thread.
 * Read the CPU's stack pointer `rsp', and then round that
 * down to the start of a page.  Since `struct thread' is
 * always at the beginning of a page and the stack pointer is
 * somewhere in the middle, this locates the curent thread. */
#define running_thread() ((struct thread *) (pg_round_down (rrsp ())))


// Global descriptor table for the thread_start.
// Because the gdt will be setup after the thread_init, we should
// setup temporal gdt first.
static uint64_t gdt[3] = { 0, 0x00af9a000000ffff, 0x00cf92000000ffff };

/* Initializes the threading system by transforming the code
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
thread_init (void) {
	ASSERT (intr_get_level () == INTR_OFF);

	/* Reload the temporal gdt for the kernel
	 * This gdt does not include the user context.
	 * The kernel will rebuild the gdt with user context, in gdt_init (). */
	struct desc_ptr gdt_ds = {
		.size = sizeof (gdt) - 1,
		.address = (uint64_t) gdt
	};
	lgdt (&gdt_ds);

	/* Init the globla thread context */
	// 여기서 lock을 안걸어주면 같은 번호를 가진 스레드가 여러 개
	// 생길 수가 있어서 lock을 걸어줘야함.
	lock_init (&tid_lock);
	list_init (&ready_list);
	list_init (&destruction_req);

	/* Set up a thread structure for the running thread. */
	initial_thread = running_thread ();
	init_thread (initial_thread, "main", PRI_DEFAULT);
	initial_thread->status = THREAD_RUNNING;
	initial_thread->tid = allocate_tid ();
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) {
	/* Create the idle thread. */
	struct semaphore idle_started;
	sema_init (&idle_started, 0);
	thread_create ("idle", PRI_MIN, idle, &idle_started);

	/* Start preemptive thread scheduling. */
	intr_enable ();

	/* Wait for the idle thread to initialize idle_thread. */
	sema_down (&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) {
	struct thread *t = thread_current ();

	/* Update statistics. */
	if (t == idle_thread)
		idle_ticks++;
#ifdef USERPROG
	else if (t->pml4 != NULL)
		user_ticks++;
#endif
	else
		kernel_ticks++;

	/* Enforce preemption. */
	if (++thread_ticks >= TIME_SLICE)
		intr_yield_on_return ();
}

/* Prints thread statistics. */
void
thread_print_stats (void) {
	printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
			idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
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
		thread_func *function, void *aux) {
	struct thread *t;
	tid_t tid;

	ASSERT (function != NULL);

	/* Allocate thread. */
	t = palloc_get_page (PAL_ZERO);
	if (t == NULL)
		return TID_ERROR;

	/* Initialize thread. */
	init_thread (t, name, priority);
	tid = t->tid = allocate_tid ();

	/* Call the kernel_thread if it scheduled.
	 * Note) rdi is 1st argument, and rsi is 2nd argument. */
	t->tf.rip = (uintptr_t) kernel_thread;
	t->tf.R.rdi = (uint64_t) function;
	t->tf.R.rsi = (uint64_t) aux;
	t->tf.ds = SEL_KDSEG;
	t->tf.es = SEL_KDSEG;
	t->tf.ss = SEL_KDSEG;
	t->tf.cs = SEL_KCSEG;
	t->tf.eflags = FLAG_IF;

	/* Add to run queue. */
	thread_unblock (t);
	if (check_priority_threads())
	{
		thread_yield();
	}
	return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) {
	ASSERT (!intr_context ());
	ASSERT (intr_get_level () == INTR_OFF);
	thread_current ()->status = THREAD_BLOCKED;
	schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */

// 오류나는 코드
// void
// thread_unblock (struct thread *t) {

// 	enum intr_level old_level; 	// 인터럽트 상태를 저장하는 변수. 
// 	struct thread *curr = thread_current ();
// 	// 함수 내부에서 인터럽트를 비활성화한 후 완료되면 원래 상태로 복원합니다.

// 	ASSERT (is_thread (t));

// 	ASSERT (t->status == THREAD_BLOCKED);
// 	old_level = intr_disable ();
// 	list_insert_ordered (&ready_list, &t->elem, priority_greater, NULL);
// 	t->status = THREAD_READY;
// 	intr_set_level (old_level);
// 	struct thread *head_t = list_entry(list_begin(&ready_list), struct thread, elem);
// 	if (head_t->priority > curr->priority) {
// 		thread_yield();
// 	}
// 	//차단된 스레드를 준비 리스트(ready_list) 끝에 추가
// }
void
thread_unblock (struct thread *t) {

	enum intr_level old_level; 	// 인터럽트 상태를 저장하는 변수. 
	// 함수 내부에서 인터럽트를 비활성화한 후 완료되면 원래 상태로 복원합니다.

	ASSERT (is_thread (t));

	ASSERT (t->status == THREAD_BLOCKED);
	
	old_level = intr_disable ();
	list_insert_ordered (&ready_list, &t->elem, priority_greater, NULL);
	t->status = THREAD_READY;
	
	intr_set_level (old_level);
}

bool
priority_greater (const struct list_elem *a, const struct list_elem *b, void *aux)
{	
	struct thread *thread_a = list_entry(a, struct thread, elem);
	struct thread *thread_b = list_entry(b, struct thread, elem);
	
	return thread_a->priority > thread_b->priority;
}

bool donate_high_priority(const struct list_elem *a, const struct list_elem *b, void *aux)
{
	const struct thread *priority_a = list_entry(a, struct thread, donation_elem);
	const struct thread *priority_b = list_entry(b, struct thread, donation_elem);
	return priority_a->priority > priority_b->priority;
}

bool check_priority_threads()
{
	if (list_empty(&ready_list)|| thread_current()==idle_thread || (intr_context()))
	{
		return false;
	}
	if (thread_current()->priority < list_entry(list_front(&ready_list), struct thread, elem)->priority)
	{
		return true;
	}
	return false;
}

/* Returns the name of the running thread. */
const char *
thread_name (void) {
	return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) {
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

/* Returns the running thread's tid. */
tid_t
thread_tid (void) {
	return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) {
	ASSERT (!intr_context ());

#ifdef USERPROG
	process_exit ();
#endif

	/* Just set our status to dying and schedule another process.
	   We will be destroyed during the call to schedule_tail(). */
	intr_disable ();
	do_schedule (THREAD_DYING);
	NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) {
	struct thread *curr = thread_current ();  // 1. 현재 실행 중인 스레드를 가져옴
	enum intr_level old_level;

	ASSERT (!intr_context ());

	old_level = intr_disable ();  // 2. 인터럽트를 비활성화
	if (curr != idle_thread)  // 3. 현재 스레드가 idle 스레드가 아니라면
		list_insert_ordered (&ready_list, &curr->elem, priority_greater, NULL);
	do_schedule (THREAD_READY);  // 5. 스케줄링을 통해 다른 스레드를 실행
	intr_set_level (old_level);  // 6. 이전 인터럽트 상태로 복원
}

/* Sets the current thread's priority to NEW_PRIORITY. */
/* 현재 스레드의 우선 순위를 NEW_PRIORITY로 설정합니다. */
void thread_set_priority(int new_priority)
{
	struct thread *t = thread_current();
	// list_entry(list_front(&sleep_list), struct thread, elem)->wake_ticks
	t->priority = new_priority;
	t->init_priority = new_priority;

	refresh_priority();
	if (check_priority_threads())
	{
		thread_yield();
	}
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) {
	return thread_current ()->priority;
}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice UNUSED) {
	/* TODO: Your implementation goes here */
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) {
	/* TODO: Your implementation goes here */
	return 0;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) {
	/* TODO: Your implementation goes here */
	return 0;
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) {
	/* TODO: Your implementation goes here */
	return 0;
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) {
	struct semaphore *idle_started = idle_started_;

	idle_thread = thread_current ();
	sema_up (idle_started);

	for (;;) {
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

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) {
	ASSERT (function != NULL);

	intr_enable ();       /* The scheduler runs with interrupts off. */
	function (aux);       /* Execute the thread function. */
	thread_exit ();       /* If function() returns, kill the thread. */
}


/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority) {
	ASSERT (t != NULL);
	ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
	ASSERT (name != NULL);

	memset (t, 0, sizeof *t);
	t->status = THREAD_BLOCKED;
	strlcpy (t->name, name, sizeof t->name);
	t->tf.rsp = (uint64_t) t + PGSIZE - sizeof (void *);
	t->priority = priority;
	t->magic = THREAD_MAGIC;

	/* --- Project 1.4 priority donation --- */
	/* --- 자료구조 초기화 --- */
	t->init_priority = priority;
	t->wait_on_lock = NULL;
	list_init(&t->donations);
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) {
	if (list_empty (&ready_list))
		return idle_thread;
	else
		return list_entry (list_pop_front (&ready_list), struct thread, elem);
}

/* Use iretq to launch the thread */
void
do_iret (struct intr_frame *tf) {
	__asm __volatile(
			"movq %0, %%rsp\n"
			"movq 0(%%rsp),%%r15\n"
			"movq 8(%%rsp),%%r14\n"
			"movq 16(%%rsp),%%r13\n"
			"movq 24(%%rsp),%%r12\n"
			"movq 32(%%rsp),%%r11\n"
			"movq 40(%%rsp),%%r10\n"
			"movq 48(%%rsp),%%r9\n"
			"movq 56(%%rsp),%%r8\n"
			"movq 64(%%rsp),%%rsi\n"
			"movq 72(%%rsp),%%rdi\n"
			"movq 80(%%rsp),%%rbp\n"
			"movq 88(%%rsp),%%rdx\n"
			"movq 96(%%rsp),%%rcx\n"
			"movq 104(%%rsp),%%rbx\n"
			"movq 112(%%rsp),%%rax\n"
			"addq $120,%%rsp\n"
			"movw 8(%%rsp),%%ds\n"
			"movw (%%rsp),%%es\n"
			"addq $32, %%rsp\n"
			"iretq"
			: : "g" ((uint64_t) tf) : "memory");
}

/* Switching the thread by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function. */
static void
thread_launch (struct thread *th) {
	uint64_t tf_cur = (uint64_t) &running_thread ()->tf;
	uint64_t tf = (uint64_t) &th->tf;
	ASSERT (intr_get_level () == INTR_OFF);

	/* The main switching logic.
	 * We first restore the whole execution context into the intr_frame
	 * and then switching to the next thread by calling do_iret.
	 * Note that, we SHOULD NOT use any stack from here
	 * until switching is done. */
	__asm __volatile (
			/* Store registers that will be used. */
			"push %%rax\n"
			"push %%rbx\n"
			"push %%rcx\n"
			/* Fetch input once */
			"movq %0, %%rax\n"
			"movq %1, %%rcx\n"
			"movq %%r15, 0(%%rax)\n"
			"movq %%r14, 8(%%rax)\n"
			"movq %%r13, 16(%%rax)\n"
			"movq %%r12, 24(%%rax)\n"
			"movq %%r11, 32(%%rax)\n"
			"movq %%r10, 40(%%rax)\n"
			"movq %%r9, 48(%%rax)\n"
			"movq %%r8, 56(%%rax)\n"
			"movq %%rsi, 64(%%rax)\n"
			"movq %%rdi, 72(%%rax)\n"
			"movq %%rbp, 80(%%rax)\n"
			"movq %%rdx, 88(%%rax)\n"
			"pop %%rbx\n"              // Saved rcx
			"movq %%rbx, 96(%%rax)\n"
			"pop %%rbx\n"              // Saved rbx
			"movq %%rbx, 104(%%rax)\n"
			"pop %%rbx\n"              // Saved rax
			"movq %%rbx, 112(%%rax)\n"
			"addq $120, %%rax\n"
			"movw %%es, (%%rax)\n"
			"movw %%ds, 8(%%rax)\n"
			"addq $32, %%rax\n"
			"call __next\n"         // read the current rip.
			"__next:\n"
			"pop %%rbx\n"
			"addq $(out_iret -  __next), %%rbx\n"
			"movq %%rbx, 0(%%rax)\n" // rip
			"movw %%cs, 8(%%rax)\n"  // cs
			"pushfq\n"
			"popq %%rbx\n"
			"mov %%rbx, 16(%%rax)\n" // eflags
			"mov %%rsp, 24(%%rax)\n" // rsp
			"movw %%ss, 32(%%rax)\n"
			"mov %%rcx, %%rdi\n"
			"call do_iret\n"
			"out_iret:\n"
			: : "g"(tf_cur), "g" (tf) : "memory"
			);
}


/* 새로운 프로세스를 스케줄링합니다. 이 함수가 호출될 때 인터럽트는 꺼져 있어야 합니다.
 * 이 함수는 현재 스레드의 상태를 status로 수정한 다음
 * 실행할 다른 스레드를 찾아 전환합니다.
 * schedule()에서 printf()를 호출하는 것은 안전하지 않습니다. */
// 실행 중인 스레드를 다른 상태로 전환하고, 스케줄링 작업을 실행
static void
do_schedule(int status)
{
	// 인터럽트 꺼져있는지 확인 / 스레드의 상태를 변경하는
	// 작업은 원자적으로 이루어져야 하므로, 인터럽트가 꺼져 있어야 안전
	ASSERT(intr_get_level() == INTR_OFF);				// 인터럽트가 비활성화된 상태를 확인
	ASSERT(thread_current()->status == THREAD_RUNNING); // 현재 스레드가 실행 중임을 확인

	while (!list_empty(&destruction_req))
	{ // 파괴 요청 목록이 비어 있지 않은 경우
		struct thread *victim =
			list_entry(list_pop_front(&destruction_req), struct thread, elem); // 파괴할 스레드를 찾음
		palloc_free_page(victim);											   // 해당 스레드의 페이지를 해제
	}
	thread_current()->status = status; // 현재 스레드의 상태를 업데이트
	schedule();						   // 스케줄링 실행
}

static void
schedule(void)
{
	struct thread *curr = running_thread();		// 현재 실행 중인 스레드
	struct thread *next = next_thread_to_run(); // 다음에 실행할 스레드

	ASSERT(intr_get_level() == INTR_OFF);	// 인터럽트가 비활성화된 상태를 확인
	ASSERT(curr->status != THREAD_RUNNING); // 현재 스레드가 더 이상 실행 중이 아님을 확인
	ASSERT(is_thread(next));				// 다음 스레드가 유효한 스레드인지 확인
	/* 실행 중으로 표시합니다. */
	next->status = THREAD_RUNNING; // 다음 스레드를 실행 상태로 설정

	/* 새로운 타임 슬라이스를 시작합니다. */
	thread_ticks = 0;

#ifdef USERPROG
	/* 새 주소 공간을 활성화합니다. */
	process_activate(next); // 사용자 프로그램의 주소 공간 활성화
#endif

	if (curr != next)
	{
		/* 전환된 스레드가 죽어가는 경우, 그 struct thread를 파괴합니다.
		   이 작업은 늦게 이루어져야 하며, thread_exit()에서 스레드가
		   스스로 파괴되지 않도록 해야 합니다.
		   스택이 여전히 사용 중이므로 페이지 해제 요청을
		   큐에 추가합니다.
		   실제 파괴 로직은 schedule()의 시작 부분에서 호출됩니다. */
		if (curr && curr->status == THREAD_DYING && curr != initial_thread)
		{
			ASSERT(curr != next);
			list_push_back(&destruction_req, &curr->elem); // 파괴 요청 목록에 추가
		}

		/* 스레드를 전환하기 전에, 현재 실행 중인 정보를 저장합니다. */
		thread_launch(next); // 새로운 스레드 실행
	}
}

void donate_priority()
{
	struct thread *now_thread = thread_current();
	struct thread *holder;
	int depth = 0;
	while (depth < 8 && now_thread->wait_on_lock != NULL)
	{
		holder = now_thread->wait_on_lock->holder;
		if (holder == NULL) // holder가 NULL인 경우 탈출
			break;
		// 현재 스레드의 우선순위가 더 높다면 기부
		if (holder->priority < now_thread->priority)
		{
			holder->priority = now_thread->priority;
		}
		now_thread = holder;
		depth++;
	}
}

/* priority */
void remove_with_lock(struct lock *lock)
{
	struct thread *now_thread = thread_current();
	struct list_elem *e;
	for (e = list_begin(&now_thread->donations); e != list_end(&now_thread->donations); e = list_next(e))
	{
		struct thread *th = list_entry(e, struct thread, donation_elem);
		if (th->wait_on_lock == lock)
		{
			list_remove(&th->donation_elem);
		}
	}
}
void refresh_priority()
{
	struct thread *current_thread = thread_current();

	// 1. 원래의 우선순위로 초기화
	current_thread->priority = current_thread->init_priority;

	// 2. 기부받은 우선순위가 있는 경우 가장 높은 우선순위로 갱신
	if (!list_empty(&current_thread->donations))
	{
		list_sort(&current_thread->donations, donate_high_priority, NULL);
		struct thread *highest_donor = list_entry(list_front(&current_thread->donations), struct thread, donation_elem);
		if (current_thread->priority < highest_donor->priority)
		{
			current_thread->priority = highest_donor->priority;
		}
	}
}

/* 새 스레드에 사용할 tid를 반환합니다. */
static tid_t
allocate_tid(void)
{
	static tid_t next_tid = 1; // 다음에 사용할 tid 값
	tid_t tid;

	lock_acquire(&tid_lock); // tid 락을 획득하여 동시 접근을 방지
	tid = next_tid++;		 // 새로운 tid를 할당하고 값 증가
	lock_release(&tid_lock); // 락 해제

	return tid; // 할당된 tid 반환
}