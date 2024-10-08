#include "devices/timer.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include "threads/interrupt.h"
#include "threads/io.h"
#include "threads/synch.h"
#include "threads/thread.h"

/* See [8254] for hardware details of the 8254 timer chip. */

#if TIMER_FREQ < 19
#error 8254 timer requires TIMER_FREQ >= 19
#endif
#if TIMER_FREQ > 1000
#error TIMER_FREQ <= 1000 recommended
#endif

/* Number of timer ticks since OS booted. */
static int64_t ticks;
static struct list sleep_list;

/* Number of loops per timer tick.
   Initialized by timer_calibrate(). */
static unsigned loops_per_tick;

static intr_handler_func timer_interrupt;
static bool too_many_loops (unsigned loops);
static void busy_wait (int64_t loops);
static void real_time_sleep (int64_t num, int32_t denom);

/* Sets up the 8254 Programmable Interval Timer (PIT) to
   interrupt PIT_FREQ times per second, and registers the
   corresponding interrupt. */
void
timer_init (void) {
	/* 8254 input frequency divided by TIMER_FREQ, rounded to
	   nearest. */
	uint16_t count = (1193180 + TIMER_FREQ / 2) / TIMER_FREQ;

	outb (0x43, 0x34);    /* CW: counter 0, LSB then MSB, mode 2, binary. */
	outb (0x40, count & 0xff);
	outb (0x40, count >> 8);
	list_init(&sleep_list); // sleeplist 초기화.

	intr_register_ext (0x20, timer_interrupt, "8254 Timer");
}

/* Calibrates loops_per_tick, used to implement brief delays. */
void
timer_calibrate (void) {
	unsigned high_bit, test_bit;

	ASSERT (intr_get_level () == INTR_ON);
	printf ("Calibrating timer...  ");

	/* Approximate loops_per_tick as the largest power-of-two
	   still less than one timer tick. */
	loops_per_tick = 1u << 10;
	while (!too_many_loops (loops_per_tick << 1)) {
		loops_per_tick <<= 1;
		ASSERT (loops_per_tick != 0);
	}

	/* Refine the next 8 bits of loops_per_tick. */
	high_bit = loops_per_tick;
	for (test_bit = high_bit >> 1; test_bit != high_bit >> 10; test_bit >>= 1)
		if (!too_many_loops (high_bit | test_bit))
			loops_per_tick |= test_bit;

	printf ("%'"PRIu64" loops/s.\n", (uint64_t) loops_per_tick * TIMER_FREQ);
}

/* Returns the number of timer ticks since the OS booted. */
int64_t
timer_ticks (void) {
	enum intr_level old_level = intr_disable ();  // 1. 인터럽트를 비활성화하고 현재 인터럽트 상태를 저장
	int64_t t = ticks;                            // 2. 전역 변수 `ticks`의 값을 읽음 (현재까지 경과된 틱)
	intr_set_level (old_level);                   // 3. 이전 인터럽트 상태로 복원
	barrier ();                                   // 4. 컴파일러 최적화 방지
	return t;                                     // 5. 읽어온 틱 값을 반환
}

/* Returns the number of timer ticks elapsed since THEN, which
   should be a value once returned by timer_ticks(). */
int64_t
timer_elapsed (int64_t then) {
	return timer_ticks () - then;
}

// 지정된 시간(틱 단위)동안 현재 스레드를 중단시키는 역할
void 
timer_sleep (int64_t ticks) {
	struct thread *this_thread = thread_current();  // 현재 실행중인 쓰레드 가져오기
	int64_t start = timer_ticks ();					// 1. 현재 시간을 가져옴
	ASSERT (intr_get_level () == INTR_ON);          // 2. 현재 인터럽트가 ON 상태 확인
	enum intr_level old_level = intr_disable ();	// 3. 인터럽트 off
	this_thread->wake_ticks = start + ticks;		// 4. 현재 쓰레드에
	list_push_back(&sleep_list, &this_thread->elem); 
	thread_block();
	intr_set_level (old_level);  
}

/* Suspends execution for approximately MS milliseconds. */
void
timer_msleep (int64_t ms) {
	real_time_sleep (ms, 1000);
}

/* Suspends execution for approximately US microseconds. */
void
timer_usleep (int64_t us) {
	real_time_sleep (us, 1000 * 1000);
}

/* Suspends execution for approximately NS nanoseconds. */
void
timer_nsleep (int64_t ns) {
	real_time_sleep (ns, 1000 * 1000 * 1000);
}

/* Prints timer statistics. */
void
timer_print_stats (void) {
	printf ("Timer: %"PRId64" ticks\n", timer_ticks ());
}

/* Timer interrupt handler. */
/* timer_interrupt에서 하는 일
1. 매틱마다 timer_interrupt가 발생한다. 전역변수 ticks +1 

2. sleep_list 관리
- sleep_list 안에 wake 해야할 쓰레드가 있으면 깨워주기
- 깨울 때 깨운 애를 unblock 처리해주고 sleep_list 목록에서 제거하기

3. 라운드 로빈(RR) 기능 구현
- thread_tick()에서 4틱 마다 실행중인 스레드를 Ready_list 맨 뒤로 보내주기
*/
static void
timer_interrupt (struct intr_frame *args UNUSED) {
    ticks++;  // 1. 매틱마다 전역변수 ticks 증가

    struct list_elem *e = list_begin(&sleep_list);
    while (e != list_end(&sleep_list)) {
        struct thread *t = list_entry(e, struct thread, elem);

        // 2. 현재 tick이 wake_ticks에 도달했는지 확인
        if (ticks >= t->wake_ticks) {
            e = list_remove(e);  // 리스트에서 제거하고 다음 요소로 이동
            thread_unblock(t);   // 스레드를 깨움
        } else {
            e = list_next(e);    // 리스트의 다음 요소로 이동
        }
    }

    // 3. 라운드 로빈(RR) 기능 구현: 4틱마다 스레드를 Ready_list로 보냄
    thread_tick();
}


/* Returns true if LOOPS iterations waits for more than one timer
   tick, otherwise false. */
static bool
too_many_loops (unsigned loops) {
	/* Wait for a timer tick. */
	int64_t start = ticks;
	while (ticks == start)
		barrier ();

	/* Run LOOPS loops. */
	start = ticks;
	busy_wait (loops);

	/* If the tick count changed, we iterated too long. */
	barrier ();
	return start != ticks;
}

/* Iterates through a simple loop LOOPS times, for implementing
   brief delays.

   Marked NO_INLINE because code alignment can significantly
   affect timings, so that if this function was inlined
   differently in different places the results would be difficult
   to predict. */
static void NO_INLINE
busy_wait (int64_t loops) {
	while (loops-- > 0)
		barrier ();
}

/* Sleep for approximately NUM/DENOM seconds. */
static void
real_time_sleep (int64_t num, int32_t denom) {
	/* Convert NUM/DENOM seconds into timer ticks, rounding down.

	   (NUM / DENOM) s
	   ---------------------- = NUM * TIMER_FREQ / DENOM ticks.
	   1 s / TIMER_FREQ ticks
	   */
	int64_t ticks = num * TIMER_FREQ / denom;

	ASSERT (intr_get_level () == INTR_ON);
	if (ticks > 0) {
		/* We're waiting for at least one full timer tick.  Use
		   timer_sleep() because it will yield the CPU to other
		   processes. */
		timer_sleep (ticks);
	} else {
		/* Otherwise, use a busy-wait loop for more accurate
		   sub-tick timing.  We scale the numerator and denominator
		   down by 1000 to avoid the possibility of overflow. */
		ASSERT (denom % 1000 == 0);
		busy_wait (loops_per_tick * num / 1000 * TIMER_FREQ / (denom / 1000));
	}
}