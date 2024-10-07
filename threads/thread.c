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
/* struct thread의 `magic` 멤버에 대한 랜덤 값.
   스택 오버플로우를 감지하는 데 사용됨. 자세한 내용은 thread.h 상단의
   큰 주석을 참조하세요. */
#define THREAD_MAGIC 0xcd6abf4b

/* 기본 스레드에 대한 랜덤 값
   이 값을 수정하지 마세요. */
#define THREAD_BASIC 0xd42df210

/* THREAD_READY 상태의 프로세스 목록, 즉 실행 준비가 완료되었지만
   실제로 실행되지 않은 프로세스 목록. */
static struct list ready_list;
static struct list sleep_list;

/* 유휴 스레드. */
static struct thread *idle_thread;

/* 초기 스레드, init.c:main()을 실행하는 스레드. */
static struct thread *initial_thread;

/* allocate_tid()에서 사용하는 락. */
static struct lock tid_lock;

/* 스레드 파괴 요청들 */
static struct list destruction_req;

/* 통계. */
static long long idle_ticks;   /* 유휴 상태로 보낸 타이머 틱 수. */
static long long kernel_ticks; /* 커널 스레드에서의 타이머 틱 수. */
static long long user_ticks;   /* 사용자 프로그램에서의 타이머 틱 수. */

/* 스케줄링. */
#define TIME_SLICE 4		  /* 각 스레드에 할당된 타이머 틱 수. */
static unsigned thread_ticks; /* 마지막 양보 이후의 타이머 틱 수. */

/* false인 경우(기본값), 라운드-로빈 스케줄러 사용.
   true인 경우, 다단계 피드백 큐 스케줄러 사용.
   커널 명령줄 옵션 "-o mlfqs"로 제어됨. */
bool thread_mlfqs;

static void kernel_thread(thread_func *, void *aux);

static void idle(void *aux UNUSED);
static struct thread *next_thread_to_run(void);
static void init_thread(struct thread *, const char *name, int priority);
static void do_schedule(int status);
static void schedule(void);
static tid_t allocate_tid(void);

/* T가 유효한 스레드를 가리키는 것으로 보이면 true를 반환. */
#define is_thread(t) ((t) != NULL && (t)->magic == THREAD_MAGIC)

/* 실행 중인 스레드를 반환.
 * CPU의 스택 포인터 `rsp`를 읽은 다음,
 * 페이지의 시작 부분으로 반올림합니다. `struct thread`는
 * 항상 페이지의 시작 부분에 위치하고 스택 포인터는
 * 중간에 있으므로, 이를 통해 현재 스레드를 찾습니다. */
#define running_thread() ((struct thread *)(pg_round_down(rrsp())))

// thread_start를 위한 전역 기술자 테이블.
// gdt가 thread_init 이후에 설정되기 때문에,
// 먼저 임시 gdt를 설정해야 합니다.
static uint64_t gdt[3] = {0, 0x00af9a000000ffff, 0x00cf92000000ffff};

/* 현재 실행 중인 코드를 스레드로 변환하여 스레딩 시스템을 초기화합니다.
   일반적으로는 불가능하지만, loader.S에서 스택 하단을 페이지 경계에
   맞추었기 때문에 가능합니다.

   또한 실행 큐와 tid 락을 초기화합니다.

   이 함수를 호출한 후, 페이지 할당자를 초기화하기 전에
   thread_create()로 스레드를 만들려고 하지 마십시오.

   이 함수가 끝날 때까지 thread_current()를 호출하는 것은 안전하지 않습니다. */
void thread_init(void)
{
	// 스레드 시스템을 초기화하는 역할
	// 인터럽트가 비활성화된 상태인지 확인하는 assert
	// 스레드 시스템 초기화하는 동안 인터럽트가 꺼져있어야 함
	ASSERT(intr_get_level() == INTR_OFF);

	/* 커널을 위한 임시 gdt(global Descriptor Table) 를 로드합니다.
	 * 이 gdt는 사용자 컨텍스트를 포함하지 않습니다.
	 * 커널은 gdt_init()에서 사용자 컨텍스트와 함께 gdt를 다시 빌드합니다. */
	/* gdt_ds는 GDT의 크기와 주소를 저장하는 구조체
	lgdt()는 이를 CPU에 로드하는 함수로, CPU의 메모리 보호 모델을 설정하는 데 사용
	여기서는 커널의 기본 메모리 영역을 설정하는 임시 GDT를 사용
	*/
	// 메모리 구역을 나누고 그 구역들에 대한 규칙을 설정
	struct desc_ptr gdt_ds = {
		.size = sizeof(gdt) - 1,
		.address = (uint64_t)gdt};
	lgdt(&gdt_ds);

	/* 전역 스레드 컨텍스트를 초기화합니다. */
	// 스레드 식별자(TID)를 생성할 때 사용할 락을 초기화
	lock_init(&tid_lock);
	// 실행 준비가 된 스레드들을 저장할 준비 리스트를 초기화
	list_init(&ready_list);
	// 잠잘 준비가 된 스레드들을 저장할 수면 리스트를 초기화
	list_init(&sleep_list);
	// 파괴 요청이 들어온 스레드들을 저장할 리스트를 초기화
	list_init(&destruction_req);

	/* 실행 중인 스레드를 위한 스레드 구조체를 설정합니다. */
	// 현재 실행 중인 스레드를 반환 // 해당 시점에는 메인슬드가 실행되고 있고 이가 initial_thread
	initial_thread = running_thread();
	// 스레드를 초기화한다. "main" 이름과 기본 우선순위로 초기화
	init_thread(initial_thread, "main", PRI_DEFAULT);
	// 초기 스레드 상태가 스레드 실행중임을 나타냄
	initial_thread->status = THREAD_RUNNING;
	// allocate_tid를 통해 고유한 스레드 식별자 할당
	initial_thread->tid = allocate_tid();
}

/* 인터럽트를 활성화하여 선점형 스레드 스케줄링을 시작합니다.
   또한 유휴 스레드를 생성합니다. */
void thread_start(void)
{
	/* 유휴 스레드를 생성합니다. */
	// idle_started라는 세마포어를 생성하고 초기화
	// 유휴 스레드가 올바르게 생성되었는지 확인하는 데 사용하고 세마포어의 초기값은 0
	struct semaphore idle_started;
	sema_init(&idle_started, 0);
	// 유휴 스레드 생성 (idel) 우선순위는 min 작업 루틴은 idel이고 세마포어를 통해 알려줌
	thread_create("idle", PRI_MIN, idle, &idle_started);

	/* 선점형 스레드 스케줄링을 시작합니다. */
	// 인터럽트가 활성화되면 CPU는 특정 조건에 따라 다른 스레드로 전환가능
	intr_enable();

	/* 유휴 스레드가 idle_thread를 초기화할 때까지 대기합니다. */
	sema_down(&idle_started);
}

/* 각 타이머 틱에서 타이머 인터럽트 핸들러가 호출합니다.
   따라서 이 함수는 외부 인터럽트 컨텍스트에서 실행됩니다. */
// 인터럽트는 스케줄러가 실행될 기회를 주는 것
// 현재 실행 중인 스레드가 CPU 시간을 얼마나 사용했는지 기록하고,
// 필요하면 다른 스레드에게 CPU를 넘겨줄지 결정
void thread_tick(void)
{
	// 현재 실행중인 스레드 가져옴
	struct thread *t = thread_current();

	/* 통계를 업데이트합니다. */
	if (t == idle_thread)
		idle_ticks++;
		// 사용자 프로그램이 얼마나 CPU 시간을 사용했는지 측정
#ifdef USERPROG
	else if (t->pml4 != NULL)
		user_ticks++;
#endif
	else
		kernel_ticks++;

	/* 선점 강제. */
	// 현재 실행 중인 스레드가 **타임 슬라이스(time slice)**를 다 썼는지를 검사합니다.
	//  타임 슬라이스는 스레드가 CPU를 독점하지 않도록 제한된 시간 동안만 실행되게 하는 방법
	if (++thread_ticks >= TIME_SLICE)
		// 다음 스케줄링 시점에 CPU를 다른 스레드에게 양보
		if (!list_empty(&ready_list))
		{ //
			intr_yield_on_return();
		}
}

/* 스레드 통계를 출력합니다. */
void thread_print_stats(void)
{
	printf("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
		   idle_ticks, kernel_ticks, user_ticks);
}

/* 주어진 초기 PRIORITY로 이름이 NAME인 새로운 커널 스레드를 생성합니다.
   FUNCTION에 AUX를 인자로 전달하며 실행되며, 이를 준비 큐에 추가합니다.
   새 스레드의 스레드 식별자를 반환하며, 생성에 실패하면 TID_ERROR를 반환합니다.

   thread_start()가 호출된 경우, 새 스레드는 thread_create()가 반환되기 전에
   스케줄링될 수 있습니다. 심지어 thread_create()가 반환되기 전에 종료될 수도 있습니다.
   반대로, 원래 스레드는 새 스레드가 스케줄링되기 전에 임의의 시간 동안 실행될 수 있습니다.
   순서를 보장하려면 세마포어 또는 다른 형태의 동기화를 사용하세요.

   제공된 코드는 새 스레드의 `priority` 멤버를 PRIORITY로 설정하지만,
   실제 우선 순위 스케줄링은 구현되지 않았습니다.
   우선 순위 스케줄링은 문제 1-3의 목표입니다. */
tid_t thread_create(const char *name, int priority, thread_func *function, void *aux)
{
	struct thread *t;
	tid_t tid;
	// 함수 포인터가 null인지 확인
	ASSERT(function != NULL);

	/* 스레드 할당. */
	// 새로운 스레드를 위한 메모리 페이지 할당
	// 메모리 페이지를 0으로 초기화하며 할당
	// 빈페이지로 할당
	t = palloc_get_page(PAL_ZERO);
	if (t == NULL)
		return TID_ERROR;

	/* 스레드 초기화. */
	init_thread(t, name, priority);
	// 새로 생성된 스레드 고유 id 할당
	tid = t->tid = allocate_tid();

	/* 스케줄링될 경우 kernel_thread를 호출합니다.
	 * 참고) rdi는 첫 번째 인자, rsi는 두 번째 인자입니다. */
	// 스레드가 실행할 함수
	t->tf.rip = (uintptr_t)kernel_thread;
	t->tf.R.rdi = (uint64_t)function;
	t->tf.R.rsi = (uint64_t)aux;
	// 데이터, 스택, 코드 세그먼트 설정
	// 	SEL_KDSEG: 커널 데이터 세그먼트.
	//  SEL_KCSEG: 커널 코드 세그먼트.
	t->tf.ds = SEL_KDSEG;
	t->tf.es = SEL_KDSEG;
	t->tf.ss = SEL_KDSEG;
	t->tf.cs = SEL_KCSEG;
	// 인터럽트를 활성화하는 플래그
	t->tf.eflags = FLAG_IF;

	// 현재 스레드의 자식으로 추가
    list_push_back(&thread_current()->child_list, &t->child_elem);

	/* 파일 디스크립터 테이블을 초기화해준다. */
	t->fdt = palloc_get_multiple(PAL_ZERO, FDT_PAGES);
    if (t->fdt == NULL) {
		palloc_free_multiple(t->fdt, FDT_PAGES);
        return TID_ERROR;
	}

	/* 실행 큐에 추가합니다. */
	// 스레드를 실행 준비 상태로 만든다.
	// THREAD_READY 상태로 설정하고 실행 큐에 추가
	thread_unblock(t);
	// 현재 실행중인 스레드를 ready

	if (check_priority_threads())
	{
		thread_yield();
	}
	return tid;
}
// void set_priority_thread(void)
// {
// 	ASSERT(!intr_context());				   // 1. 확인: 인터럽트 컨텍스트에서 호출되지 않았는지 검사
// 	ASSERT(intr_get_level() == INTR_OFF);	   // 2. 확인: 인터럽트가 비활성화된 상태인지 확인
// 	thread_current()->status = THREAD_BLOCKED; // 3. 현재 스레드의 상태를 BLOCKED로 변경
// 	schedule();								   // 4. 스케줄러를 호출하여 다음 스레드를 실행
// }
/* 현재 스레드를 잠자게 합니다. thread_unblock()에 의해 깨어날 때까지
   다시 스케줄링되지 않습니다.

   이 함수는 인터럽트가 꺼진 상태에서 호출되어야 합니다.
   동기화 프리미티브(synch.h의) 중 하나를 사용하는 것이 더 좋은 아이디어일 수 있습니다. */
void thread_block(void)
{
	ASSERT(!intr_context());				   // 1. 확인: 인터럽트 컨텍스트에서 호출되지 않았는지 검사
	ASSERT(intr_get_level() == INTR_OFF);	   // 2. 확인: 인터럽트가 비활성화된 상태인지 확인
	thread_current()->status = THREAD_BLOCKED; // 3. 현재 스레드의 상태를 BLOCKED로 변경
	schedule();								   // 4. 스케줄러를 호출하여 다음 스레드를 실행
}

bool less_wake_ticks(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED)
{
	const struct thread *t_a = list_entry(a, struct thread, elem);
	const struct thread *t_b = list_entry(b, struct thread, elem);
	return t_a->wake_ticks < t_b->wake_ticks;
}

bool better_priority(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED)
{
	const struct thread *t_a = list_entry(a, struct thread, elem);
	const struct thread *t_b = list_entry(b, struct thread, elem);
	return t_a->priority > t_b->priority;
}
bool donate_high_priority(const struct list_elem *a, const struct list_elem *b, void *aux)
{
	const struct thread *priority_a = list_entry(a, struct thread, donation_elem);
	const struct thread *priority_b = list_entry(b, struct thread, donation_elem);
	return priority_a->priority > priority_b->priority;
}
void thread_sleep(int64_t ticks)
{
	struct thread *th = thread_current();
	th->wake_ticks = ticks; // ticks에 도달하면 깨우도록, 깨워야 하는 시점을 저장한다.

	enum intr_level old_level = intr_disable();							// 인터럽트 비활성화
	list_insert_ordered(&sleep_list, &th->elem, less_wake_ticks, NULL); // sleep list에 넣기 (ticks순 오름차순)
	thread_block();														// 현재 쓰레드를 waiter 리스트에 넣기
	intr_set_level(old_level);											// 인터럽트 활성화
}

void check_thread_tick(int64_t ticks)
{
	struct list_elem *e;
	struct thread *t;

	while (!list_empty(&sleep_list) && list_entry(list_front(&sleep_list), struct thread, elem)->wake_ticks <= ticks)
	{
		struct thread *awake_thread = list_entry(list_pop_front(&sleep_list), struct thread, elem);

		thread_unblock(awake_thread);
	}
}

/* 차단된 스레드 T를 실행 준비 상태로 전환합니다.
   T가 차단되지 않은 경우, 이는 오류입니다. (실행 중인 스레드를
   준비 상태로 만들려면 thread_yield()를 사용하세요.)

   이 함수는 실행 중인 스레드를 선점하지 않습니다.
   이는 중요할 수 있습니다. 호출자가 인터럽트를 직접 비활성화한 경우,
   스레드를 원자적으로 차단 해제하고 다른 데이터를 업데이트할 수 있다고 기대할 수 있습니다. */
void thread_unblock(struct thread *t)
{
	enum intr_level old_level;

	ASSERT(is_thread(t)); // 1. 스레드가 유효한지 확인합니다.

	// 2. 인터럽트를 비활성화하고 이전 상태를 저장
	// on // off 반환
	old_level = intr_disable();

	// 3. 스레드의 상태가 BLOCKED인지 확인합니다.
	ASSERT(t->status == THREAD_BLOCKED);

	// 4. 준비 리스트에 스레드를 추가합니다.
	list_insert_ordered(&ready_list, &t->elem, better_priority, NULL);

	// 5. 스레드를 THREAD_READY 상태로 전환합니다.
	t->status = THREAD_READY;

	// 6. 인터럽트를 원래 상태로 복원합니다.
	intr_set_level(old_level);
}

/* 실행 중인 스레드의 이름을 반환합니다. */
const char *
thread_name(void)
{
	return thread_current()->name;
}

/* 실행 중인 스레드를 반환합니다.
   이것은 running_thread()와 몇 가지 일관성 검사를 추가한 것입니다.
   자세한 내용은 thread.h 상단의 큰 주석을 참조하세요. */
struct thread *
thread_current(void)
{
	struct thread *t = running_thread();

	/* T가 실제로 스레드인지 확인합니다.
	   이 어설션들 중 하나라도 실패하면, 스레드가 스택 오버플로우되었을 수 있습니다.
	   각 스레드는 4kB 미만의 스택을 가지고 있으므로,
	   몇 가지 큰 자동 배열이나 중간 정도의 재귀는 스택 오버플로우를 유발할 수 있습니다. */
	ASSERT(is_thread(t));
	ASSERT(t->status == THREAD_RUNNING);

	return t;
}

/* 실행 중인 스레드의 tid를 반환합니다. */
tid_t thread_tid(void)
{
	return thread_current()->tid;
}

/* 현재 스레드를 스케줄링에서 제거하고 이를 파괴합니다.
   이 함수는 호출자에게 반환되지 않습니다. */
void thread_exit(void)
{
	// 인터럽트 컨텍스트에서 이 함수가 호출되지 않았는지 확인
	ASSERT(!intr_context());

#ifdef USERPROG
	process_exit();
#endif

	/* 단순히 상태를 dying으로 설정하고 다른 프로세스를 스케줄링합니다.
	   우리는 schedule_tail() 호출 중에 파괴될 것입니다. */
	// 인터럽트 비활성
	intr_disable();
	// 스케줄링을
	// 강제로 실행하여 다른 스레드로 전환합니다.
	do_schedule(THREAD_DYING);
	// 함수가 여기로 도달하면 안됨
	// 도달하면 실행중단하기 위해 NOT_REACHED 호출
	NOT_REACHED();
}

/* CPU를 양보합니다. 현재 스레드는 잠자지 않고,
   스케줄러의 임의대로 즉시 다시 스케줄링될 수 있습니다. */
void thread_yield(void)
{
	struct thread *curr = thread_current();
	enum intr_level old_level; // 인터럽트 상태를 저장할 변수
	ASSERT(!intr_context());
	// 인터럽트 비활성화
	old_level = intr_disable();
	// 유휴 스레드가 아니면
	if (curr != idle_thread)
		// ready 리스트에 집어넣기
		list_insert_ordered(&ready_list, &curr->elem, better_priority, NULL);
	// 스케쥴러 동작
	do_schedule(THREAD_READY);
	intr_set_level(old_level);
}
bool check_priority_threads()
{
	if (list_empty(&ready_list))
	{
		return false;
	}
	if (thread_current()->priority < list_entry(list_front(&ready_list), struct thread, elem)->priority)
	{
		return true;
	}
	return false;
}

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

/* 현재 스레드의 우선 순위를 반환합니다. */
int thread_get_priority(void)
{
	return thread_current()->priority;
}

/* 현재 스레드의 nice 값을 NICE로 설정합니다. */
// 스레드의 "nice" 값을 설정하는 함수입니다.
// "nice" 값은 스레드가 얼마나 CPU를
// 많이 또는 적게 받을지를 조정하는 값입니다.
// 높은 "nice" 값은 스레드가 CPU를 덜 받도록 하고,
// 낮은 값은 더 받도록 합니다
// nice 높을수록 양보하는 성질
void thread_set_nice(int nice UNUSED)
{
	/* TODO: 구현하세요 */
}

/* 현재 스레드의 nice 값을 반환합니다. */
// nice :  CPU 점유율을 조정
int thread_get_nice(void)
{
	/* TODO: 구현하세요 */
	return 0;
}

/* 시스템의 평균 부하 값을 100배하여 반환합니다. */
// 시스템에서 얼마나 많은 스레드가 실행 대기 상태인지를 나타내며,
// 100배로 스케일된 값을 반환
int thread_get_load_avg(void)
{
	/* TODO: 구현하세요 */
	return 0;
}

/* 현재 스레드의 recent_cpu 값을 100배하여 반환합니다. */
// 현재 스레드가 얼마나 많은 CPU 시간을 사용했는지를
// 100배로 반환하는 함수입니다.
// CPU 사용량을 기반으로 스레드의 우선순위를 계산하는 데 사용될 수 있습니다.
int thread_get_recent_cpu(void)
{
	/* TODO: 구현하세요 */
	return 0;
}

/* 유휴 스레드. 실행할 다른 스레드가 없을 때 실행됩니다.

   유휴 스레드는 thread_start()에 의해 처음으로 준비 목록에 추가됩니다.
   처음에는 스케줄링된 후, idle_thread를 초기화하고,
   idle_thread를 계속할 수 있도록 세마포어를 "up"합니다.
   그런 다음 즉시 차단됩니다. 이후 유휴 스레드는 다시 준비 목록에 나타나지 않습니다.
   준비 목록이 비어 있을 때 next_thread_to_run()에 의해 특별한 경우로 반환됩니다. */
static void
idle(void *idle_started_ UNUSED)
{
	struct semaphore *idle_started = idle_started_;

	idle_thread = thread_current();
	sema_up(idle_started);

	for (;;)
	{
		/* 다른 스레드에게 실행 기회를 줍니다. */
		intr_disable();
		thread_block();

		/* 인터럽트를 다시 활성화하고 다음 인터럽트를 기다립니다.

		   `sti` 명령어는 다음 명령어가 완료될 때까지 인터럽트를 비활성화합니다.
		   따라서 이 두 명령어는 원자적으로 실행됩니다. 이 원자성은
		   중요합니다. 그렇지 않으면, 인터럽트가 활성화된 후,
		   대기하는 동안 인터럽트가 처리될 수 있으며, 최대 하나의 시계 틱이
		   낭비될 수 있습니다.

		   [IA32-v2a] "HLT", [IA32-v2b] "STI" 및 [IA32-v3a]
		   7.11.1 "HLT Instruction"을 참조하세요. */
		asm volatile("sti; hlt" : : : "memory");
	}
}

/* 커널 스레드의 기초로 사용되는 함수. */
static void
kernel_thread(thread_func *function, void *aux)
{
	ASSERT(function != NULL);

	intr_enable(); /* 스케줄러는 인터럽트가 비활성화된 상태에서 실행됩니다. */
	function(aux); /* 스레드 함수를 실행합니다. */
	thread_exit(); /* function()이 반환되면, 스레드를 종료합니다. */
}

/* T를 NAME이라는 이름의 차단된 스레드로 기본 초기화합니다. */
static void
init_thread(struct thread *t, const char *name, int priority)
{
	ASSERT(t != NULL);
	ASSERT(PRI_MIN <= priority && priority <= PRI_MAX);
	ASSERT(name != NULL);

	// 스레드 구조체의 메모리를 0으로 초기화
	memset(t, 0, sizeof *t);
	// 스레드 상태를 THREAD_BLOCKED로 설정 (처음에는 차단 상태로 시작)
	t->status = THREAD_BLOCKED;
	// 스레드 이름을 복사
	strlcpy(t->name, name, sizeof t->name);
	// 스레드의 스택 포인터 설정
	// 스레드 구조체의 끝부분(스택 상단)에 스택 포인터를 맞춤
	t->tf.rsp = (uint64_t)t + PGSIZE - sizeof(void *);
	t->priority = priority;
	t->magic = THREAD_MAGIC;

	t->init_priority = priority;
	
	list_init(&t->donations);	
	list_init(&(t->child_list));
	
	sema_init(&t->load_sema, 0);
	sema_init(&t->exit_sema, 0);
    sema_init(&t->wait_sema, 0);

	/* 다음 fd값을 2로 설정한다. */
	t->next_fd = 2;
}

/* 스케줄링될 다음 스레드를 선택하고 반환합니다.
   실행 큐에서 스레드를 반환해야 하며, 실행 큐가 비어 있으면 idle_thread를 반환합니다. */
static struct thread *
next_thread_to_run(void)
{
	if (list_empty(&ready_list))
		return idle_thread;
	else
		return list_entry(list_pop_front(&ready_list), struct thread, elem);
}

/* iretq를 사용하여 스레드를 실행합니다. */
// 스레드 복원
void do_iret(struct intr_frame *tf)
{
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
		: : "g"((uint64_t)tf) : "memory");
}

/* 새 스레드의 페이지 테이블을 활성화하여 스레드를 전환하고,
   이전 스레드가 종료 중이라면 이를 파괴합니다.

   이 함수가 호출될 때, 우리는 방금 이전 스레드에서 전환되었으며,
   새로운 스레드는 이미 실행 중이며 인터럽트는 여전히 비활성화되어 있습니다.

   스레드 전환이 완료될 때까지 printf()를 호출하는 것은 안전하지 않습니다.
   실제로 이는 스레드 전환이 끝난 후에 printf()를 호출해야 한다는 것을 의미합니다. */
static void
thread_launch(struct thread *th)
{
	// 현재 실행중인 스레드의 레지스터 정보 저장
	uint64_t tf_cur = (uint64_t)&running_thread()->tf;
	// 다음 스레드의 레지스터 정보 불러오기
	uint64_t tf = (uint64_t)&th->tf;
	ASSERT(intr_get_level() == INTR_OFF);

	/* 주요 스레드 전환 로직.
	 * 먼저 intr_frame에 전체 실행 컨텍스트를 복원한 후
	 * do_iret을 호출하여 다음 스레드로 전환합니다.
	 * 참고로, 전환이 완료될 때까지 스택을 사용해서는 안 됩니다. */
	__asm __volatile(
		/* 사용될 레지스터들을 저장합니다. */
		"push %%rax\n"
		"push %%rbx\n"
		"push %%rcx\n"
		/* 입력을 한 번에 가져옴 */
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
		"pop %%rbx\n" // 저장된 rcx
		"movq %%rbx, 96(%%rax)\n"
		"pop %%rbx\n" // 저장된 rbx
		"movq %%rbx, 104(%%rax)\n"
		"pop %%rbx\n" // 저장된 rax
		"movq %%rbx, 112(%%rax)\n"
		"addq $120, %%rax\n"
		"movw %%es, (%%rax)\n"
		"movw %%ds, 8(%%rax)\n"
		"addq $32, %%rax\n"
		"call __next\n" // 현재 rip를 읽습니다.
		"__next:\n"
		"pop %%rbx\n"
		"addq $(out_iret -  __next), %%rbx\n"
		"movq %%rbx, 0(%%rax)\n" // rip
		"movw %%cs, 8(%%rax)\n"	 // cs
		"pushfq\n"
		"popq %%rbx\n"
		"mov %%rbx, 16(%%rax)\n" // eflags
		"mov %%rsp, 24(%%rax)\n" // rsp
		"movw %%ss, 32(%%rax)\n"
		"mov %%rcx, %%rdi\n"
		"call do_iret\n"
		"out_iret:\n"
		: : "g"(tf_cur), "g"(tf) : "memory");
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
