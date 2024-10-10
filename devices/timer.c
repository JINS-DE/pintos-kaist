#include "devices/timer.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include "threads/interrupt.h"
#include "threads/io.h"
#include "threads/synch.h"
#include "threads/thread.h"
/* 8254 타이머 칩의 하드웨어 세부 사항은 [8254]를 참조하세요. */
// 타이머 주파수 - 1초에 발생하는 타이머 인터럽트의 횟수
#if TIMER_FREQ < 19
#error 8254 timer requires TIMER_FREQ >= 19
#endif
#if TIMER_FREQ > 1000
#error TIMER_FREQ <= 1000 recommended
#endif

/* OS 부팅 이후의 타이머 틱 수. */
static int64_t ticks;

/* 타이머 틱당 반복할 루프 수.
   timer_calibrate()에 의해 초기화됩니다. */
static unsigned loops_per_tick;

static intr_handler_func timer_interrupt;
static bool too_many_loops( unsigned loops );
static void busy_wait( int64_t loops );
static void real_time_sleep( int64_t num, int32_t denom );

/* 8254 프로그래머블 인터벌 타이머(PIT)를 설정하여
   PIT_FREQ만큼의 빈도로 인터럽트를 발생시키고,
   해당 인터럽트를 등록합니다. */
// 정기적으로 인터럽트를 발생시키도록 구성

/*
 loops_per_tick 값을 보정하는 역할을 합니다.
 이 값은 짧은 지연을 구현할 때 사용됩니다.
 짧은 시간 동안 busy-waiting을 하면서 CPU가
 다른 작업을 하지 않도록 대기 상태를 유지하는 데 사용됩니다.
 이 보정 작업은 하드웨어 타이머의 속도에 맞춰 CPU가 얼마나
 많은 루프를 돌 수 있는지를 측정
 */
void timer_init( void ) {
    /* 8254 입력 주파수를 TIMER_FREQ로 나눈 값을
       반올림하여 구합니다. */
    // PIT의 입력 클록 주파수(1.19318 MHz)
    // 1/100초 마다 1틱 올라가도록 설정
    uint16_t count = ( 1193180 + TIMER_FREQ / 2 ) / TIMER_FREQ;

    // 함수는 주어진 값(0x34)을 I/O 포트에 출력하는 함수입니다.
    // 여기서는 **I/O 포트 0x43**에 값을 출력
    // 00110100
    //  비트 6-7 카운터 선택
    // 비트 4-5 읽기/쓰기 방식
    // 비트 1-3 모드 설정 - 모드 2 주기적으로 인터럽트를 발생시키는 방식
    // 비트 0 바이너리 모드
    outb( 0x43, 0x34 ); /* CW: 카운터 0, 먼저 LSB 그다음 MSB, 모드 2, 이진 모드. */
    // 16비트를 두 번 나눠서 카운터 0에 전송하는 과정
    // 하위 8비트만 추출하여 카운터 0에 먼저 전송
    outb( 0x40, count & 0xff );
    // 오른쪽으로 8비트 이동시켜 0으로 전송
    outb( 0x40, count >> 8 );

    // 외부 인터럽트 핸들러를 등록하는 함수
    // 0x20 8254 인터럽트 인덱스가 0x20 부터 하드웨어 인터럽트 관련 번호
    // 한 틱이 지날때마다 타이머 인터럽트가 발생
    intr_register_ext( 0x20, timer_interrupt, "8254 Timer" );
}

/* 짧은 지연을 구현하기 위해 사용되는 loops_per_tick을 보정합니다. */
void timer_calibrate( void ) {
    unsigned high_bit, test_bit;

    ASSERT( intr_get_level() == INTR_ON );
    printf( "타이머 보정 중...  " );

    /* 아직 한 타이머 틱이 지나지 않은 가장 큰 2의 거듭제곱으로
       loops_per_tick을 대략적으로 설정합니다. */
    loops_per_tick = 1u << 10;
    while ( !too_many_loops( loops_per_tick << 1 ) ) {
        loops_per_tick <<= 1;
        ASSERT( loops_per_tick != 0 );
    }

    /* loops_per_tick의 다음 8비트를 세밀하게 설정합니다. */
    high_bit = loops_per_tick;
    for ( test_bit = high_bit >> 1; test_bit != high_bit >> 10; test_bit >>= 1 )
        if ( !too_many_loops( high_bit | test_bit ) ) loops_per_tick |= test_bit;

    printf( "%'" PRIu64 " loops/s.\n", (uint64_t)loops_per_tick * TIMER_FREQ );
}

/* OS 부팅 이후의 타이머 틱 수를 반환합니다. */
// 현재까지 발생한 타이머 틱의 수 반환
int64_t timer_ticks( void ) {
    enum intr_level old_level = intr_disable();
    int64_t t = ticks;
    intr_set_level( old_level );
    // 명령어 순서를 변경하지 않도록 강재하는 역할
    // 타이머 틱(ticks) 값이 정확하게 읽혀야 하고,
    // 인터럽트가 활성화되기 전에 중요한 작업들이 모두 완료
    // 다중 스레드 환경에서 여러 스레드가 메모리에 여러 작업을 할때
    // CPU가 임의로 읽기쓰기 작업을 바꾸는경우가 있어서 이를 막기 위해
    // 실행하는 함수
    barrier();
    return t;
}

/* timer_ticks()에 의해 반환된 값으로부터 경과된
   타이머 틱 수를 반환합니다. */
// 지정된 시점 이후에 얼마나 시간이 흘렀는지 계산
// timer_elapsed(start_time);
int64_t timer_elapsed( int64_t then ) { return timer_ticks() - then; }

/* 약 TICKS 만큼의 타이머 틱 동안 실행을 중단합니다. */
// 타이머 틱 수(ticks) 동안 현재 스레드의 실행을 중단하는 역할
/* TODO : timer sleep를 다시 구현한다. */
/* BUSY WAIT를 사용할 필요 없도록 구현한다. */
void timer_sleep( int64_t ticks ) {
    // 현재 시점 기록
    int64_t start = timer_ticks();

    // 현재 인터럽트 상태가 켜져있는지 검사
    ASSERT( intr_get_level() == INTR_ON );

    // 경과 시간이 원하는 타이머 틱(ticks) 수보다 작으면 계속 CPU를 양보
    // 현재 timer_ticks - start 틱보다 작으면 계속 중단

    // while (timer_elapsed(start) < ticks)
    // 	thread_yield();

    thread_sleep( start + ticks );
}

/* 약 MS 밀리초 동안 실행을 중단합니다. */
void timer_msleep( int64_t ms ) { real_time_sleep( ms, 1000 ); }

/* 약 US 마이크로초 동안 실행을 중단합니다. */
void timer_usleep( int64_t us ) { real_time_sleep( us, 1000 * 1000 ); }

/* 약 NS 나노초 동안 실행을 중단합니다. */
void timer_nsleep( int64_t ns ) { real_time_sleep( ns, 1000 * 1000 * 1000 ); }

/* 타이머 통계를 출력합니다. */
void timer_print_stats( void ) { printf( "Timer: %" PRId64 " ticks\n", timer_ticks() ); }

/* 타이머 인터럽트 핸들러. */
static void timer_interrupt( struct intr_frame *args UNUSED ) {
    // 인터럽트를 실행했으니 틱 증가

    ticks++;  // 시스템이 시작된 이후 경과한 타이머 틱 수를 증가시킴
    check_thread_tick( ticks );
    thread_tick();  // 스레드 관련 타이머 기능을 처리 // 스레드 틱도 증가시킴
}

/* LOOPS 반복이 하나의 타이머 틱 이상 대기하는 경우 true를 반환하고,
   그렇지 않은 경우 false를 반환합니다. */
// 루프 반복 횟수가 너무 많아 타이머 틱 동안 완료되지 않는지 확인
static bool too_many_loops( unsigned loops ) {
    /* 타이머 틱을 대기합니다. */
    int64_t start = ticks;    // 현재 타이머 틱 수를 저장
    while ( ticks == start )  // 새로운 타이머 틱이 발생할 때까지 대기
        barrier();            // 최적화 방지

    start = ticks;  // 현재 타이머 틱 수를 다시 저장
    /* LOOPS 횟수만큼 루프를 실행합니다. */
    busy_wait( loops );  // 주어진 횟수만큼 루프를 반복 (실제 작업 수행)

    /* 틱 카운트가 변경되었으면, 반복 횟수가 너무 많았습니다. */
    barrier();              // 최적화 방지
    return start != ticks;  // 타이머 틱이 변경되었으면 true 반환
}

/* 짧은 지연을 구현하기 위해 LOOPS 횟수만큼 간단한 루프를 반복합니다.

   코드 정렬이 타이밍에 큰 영향을 줄 수 있으므로,
   이 함수가 다른 위치에서 다르게 인라인되면 결과를 예측하기 어렵기 때문에
   NO_INLINE으로 표시되었습니다. */
// inline이면 함수를 불러오는 부분이 코드로 대체되는데
// no inline 시에 함수를 불러오는 부분에서 그대로 함수를 콜하여 직접 함수를 실행하기 때문에
// 정확한 시간을 측정할 수 있다.
static void NO_INLINE busy_wait( int64_t loops ) {
    while ( loops-- > 0 ) barrier();
}

/* NUM/DENOM 초 동안 잠자기를 합니다. */
// 시간 동안 정확하게 잠자기(sleep) 기능
static void real_time_sleep( int64_t num, int32_t denom ) {
    /* NUM/DENOM 초를 타이머 틱으로 변환하고, 내림 처리합니다.

       (NUM / DENOM) s
       ---------------------- = NUM * TIMER_FREQ / DENOM ticks.
       1 s / TIMER_FREQ ticks
       */
    // TIMER_FREQ는 초당 발생하는 타이머 인터럽트의 수
    // 주어진 시간(num / denom 초)이 몇 타이머 틱에 해당하는지 계산
    int64_t ticks = num * TIMER_FREQ / denom;
    // num / denom 초 동안 몇 개의 타이머 틱이 발생
    ASSERT( intr_get_level() == INTR_ON );
    // 타이머 틱이 1 이상이면 timer_sleep()을
    // 호출하여 CPU를 다른 프로세스에 양보
    if ( ticks > 0 ) {
        /* 적어도 한 타이머 틱 동안 기다리고 있습니다.
           timer_sleep()을 사용하여 CPU를 다른 프로세스에 양보합니다. */
        //
        timer_sleep( ticks );
    } else {
        /* 그렇지 않은 경우, 더 정확한 서브틱 타이밍을 위해
           바쁜 대기 루프를 사용합니다. 오버플로우 가능성을 피하기 위해
           분자와 분모를 1000으로 나눕니다. */
        /*
        *타이머 틱이 1보다 작은 경우,
        짧은 시간 동안 잠자기 위해
        바쁜 대기(busy-waiting) 방식을 사용합니다.
        CPU가 바쁘게 돌아가면서 loops_per_tick을 사용하여 매우
        짧은 지연을 만듭니다. loops_per_tick은 타이머 틱 내에서의
        짧은 시간 지연을 측정할 수 있도록 보정된 값입니다.
        */
        ASSERT( denom % 1000 == 0 );
        // 틱보다 짧은 시간 동안 대기하는 것
        // CPU가 얼마나 많은 반복을 수행해야 해당 시간만큼 대기할 수 있는지
        //  num / 1000 * TIMER_FREQ / (denom / 1000) -> 틱을 구하는 식 * 틱만큼 얼마나 루프를 돌아야하는지
        busy_wait( loops_per_tick * num / 1000 * TIMER_FREQ / ( denom / 1000 ) );
    }
}
