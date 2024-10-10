#include "threads/interrupt.h"
#include <debug.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include "threads/flags.h"
#include "threads/intr-stubs.h"
#include "threads/io.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "devices/timer.h"
#include "intrinsic.h"
#ifdef USERPROG
#include "userprog/gdt.h"
#endif

/* Number of x86_64 interrupts. */
#define INTR_CNT 256
/* 운영체제나 저수준 시스템 프로그래밍에서 인터럽트 벡터의 총 개수를 정의 */
/* 인터럽트 벡터 : 인터럽트 요청이 발생했을 때 어떤 코드(인터럽트 핸들러)가 실행되어야 하는지를 가리키는 포인터*/

/* Creates an gate that invokes FUNCTION.

   The gate has descriptor privilege level DPL, meaning that it
   can be invoked intentionally when the processor is in the DPL
   or lower-numbered ring.  In practice, DPL==3 allows user mode
   to call into the gate and DPL==0 prevents such calls.  Faults
   and exceptions that occur in user mode still cause gates with
   DPL==0 to be invoked.

   TYPE must be either 14 (for an interrupt gate) or 15 (for a
   trap gate).  The difference is that entering an interrupt gate
   disables interrupts, but entering a trap gate does not.  See
   [IA32-v3a] section 5.12.1.2 "Flag Usage By Exception- or
   Interrupt-Handler Procedure" for discussion. */

/* 게이트 디스크립터를 정의하는 구조체 : */
/* 인터럽트 디스크립터 테이블(IDT, Interrupt Descriptor Table)**의 항목을 구성하는 데 사용되며, 인터럽트나 예외가 발생했을 때 해당 핸들러의 주소와 관련된 메타데이터를 포함 */
struct gate {
    unsigned off_15_0 : 16;   // low 16 bits of offset in segment - [게이트에 등록된 핸들러의 주소의 하위 16비트를 저장]
    unsigned ss : 16;         // segment selector - [핸들러 코드가 위치한 세그먼트 선택자]
    unsigned ist : 3;         // # args, 0 for interrupt/trap gates - [Interrupt Stack Table(IST) 인덱스를 나타냄. 특정 인터럽트를 처리할 때 사용할 스택을 선택]
    unsigned rsv1 : 5;        // reserved(should be zero I guess) - [예약된 필드로, 항상 0이어야 합니다]
    unsigned type : 4;        // type(STS_{TG,IG32,TG32}) - [게이트의 타입. STS_TG, STS_IG32, STS_TG32 등. 주로 인터럽트 게이트(0xE), 트랩 게이트(0xF)가 사용]
    unsigned s : 1;           // must be 0 (system) - [시스템 플래그로, 항상 0, 게이트 디스크립터는 시스템 디스크립터로 취급되므로, 이 필드는 반드시 0이어야 함.]
    unsigned dpl : 2;         // descriptor(meaning new) privilege level - [DPL, 인터럽트 게이트에 접근할 수 있는 권한 레벨을 결정 (0이 가장 높음, 3이 가장 낮음)]
    unsigned p : 1;           // Present - [Present 플래그로, 게이트가 사용 가능한지 여부를 나타냅니다. 이 값이 1이면 게이트가 유효하며, 0이면 무효]
    unsigned off_31_16 : 16;  // high bits of offset in segment - [핸들러 주소의 중간 16비트를 저장]
    uint32_t off_32_63;       // 핸들러 주소의 상위 32비트를 저장합니다. x86-64 환경에서 전체 64비트 주소를 표현하기 위해 사용
    uint32_t rsv2;            // 예약된 필드로, 항상 0이어야 합니다.
};

/* The Interrupt Descriptor Table (IDT).  The format is fixed by
   the CPU.  See [IA32-v3a] sections 5.10 "Interrupt Descriptor
   Table (IDT)", 5.11 "IDT Descriptors", 5.12.1.2 "Flag Usage By
   Exception- or Interrupt-Handler Procedure". */
static struct gate idt[INTR_CNT];  // 인터럽트 디스크립터 테이블(IDT)의 정적 배열을 정의하는 코드(INTR_CNT는 IDT의 항목 수를 나타냄)

static struct desc_ptr idt_desc = {  // 포인터 구조체를 정의하고 초기화()
    .size = sizeof( idt ) - 1,
    .address = (uint64_t)idt };

/* 주어진 함수 포인터와 다양한 속성들을 바탕으로 게이트 디스크립터를 생성 */
#define make_gate( g, function, d, t )                                  \
    {                                                                   \
        ASSERT( ( function ) != NULL );                                 \
        ASSERT( ( d ) >= 0 && ( d ) <= 3 );                             \
        ASSERT( ( t ) >= 0 && ( t ) <= 15 );                            \
        *( g ) = ( struct gate ){                                       \
            .off_15_0 = (uint64_t)(function)&0xffff,                    \
            .ss = SEL_KCSEG,                                            \
            .ist = 0,                                                   \
            .rsv1 = 0,                                                  \
            .type = ( t ),                                              \
            .s = 0,                                                     \
            .dpl = ( d ),                                               \
            .p = 1,                                                     \
            .off_31_16 = ( (uint64_t)( function ) >> 16 ) & 0xffff,     \
            .off_32_63 = ( (uint64_t)( function ) >> 32 ) & 0xffffffff, \
            .rsv2 = 0,                                                  \
        };                                                              \
    }

/* Creates an interrupt gate that invokes FUNCTION with the given DPL. */
/* make_gate 매크로를 기반으로 하여, 주어진 핸들러 함수와 특정 권한 레벨(DPL)을 사용하여 인터럽트 게이트를 생성 */
#define make_intr_gate( g, function, dpl ) make_gate( ( g ), ( function ), ( dpl ), 14 )

/* Creates a trap gate that invokes FUNCTION with the given DPL. */
#define make_trap_gate( g, function, dpl ) make_gate( ( g ), ( function ), ( dpl ), 15 )  // 트랩 핸들러를 설정하기 위한 매크로

/* Interrupt handler functions for each interrupt. */
static intr_handler_func *intr_handlers[INTR_CNT];  // 인터럽트 핸들러 함수 포인터를 저장

/* Names for each interrupt, for debugging purposes. */
static const char *intr_names[INTR_CNT];  // 인터럽트 번호와 그에 해당하는 이름을 매핑하기 위한 상수 문자열 배열

/* External interrupts are those generated by devices outside the
   CPU, such as the timer.  External interrupts run with
   interrupts turned off, so they never nest, nor are they ever
   pre-empted.  Handlers for external interrupts also may not
   sleep, although they may invoke intr_yield_on_return() to
   request that a new process be scheduled just before the
   interrupt returns. */
static bool in_external_intr; /* Are we processing an external interrupt? */
static bool yield_on_return;  /* Should we yield on interrupt return? */

/* Programmable Interrupt Controller helpers. */
static void pic_init( void );
static void pic_end_of_interrupt( int irq );

/* Interrupt handlers. */
void intr_handler( struct intr_frame *args );

/* Returns the current interrupt status. */
enum intr_level
/* 현재 인터럽트 허용 상태를 확인하여 반환하는 역할 */
/* x86 아키텍처에서 사용되는 어셈블리 언어 명령어를 통해 CPU의 플래그 레지스터에서 인터럽트 플래그를 읽어옴 */
intr_get_level( void ) {
    uint64_t flags;

    /* Push the flags register on the processor stack, then pop the
       value off the stack into `flags'.  See [IA32-v2b] "PUSHF"
       and "POP" and [IA32-v3a] 5.8.1 "Masking Maskable Hardware
       Interrupts". */
    /*  pushfq: 플래그 레지스터의 값을 스택에 푸시(push)합니다. 이는 현재의 CPU 플래그 상태를 저장합니다.
            popq %0: 스택에서 값을 팝(pop)하여 flags 변수에 저장합니다. %0는 C 변수에 대응되는 자리표시자로, flags에 대한 참조입니다.
            volatile: 컴파일러에게 이 코드는 최적화하지 말라는 지시입니다. 이는 어셈블리 코드가 반드시 실행되어야 함을 보장합니다. */
    asm volatile( "pushfq; popq %0"
                  : "=g"( flags ) );

    return flags & FLAG_IF ? INTR_ON : INTR_OFF;
}

/* Enables or disables interrupts as specified by LEVEL and
   returns the previous interrupt status. */
enum intr_level
/* 주어진 인터럽트 레벨에 따라 시스템의 인터럽트 상태를 설정하는 역할 : INTR_ON 또는 INTR_OFF의 값을 받아서 인터럽트를 활성화하거나 비활성화 */
intr_set_level( enum intr_level level ) {
    /* 이 부분은 주어진 level 값에 따라 조건부로 두 함수 중 하나를 호출합니다.
            level이 INTR_ON이면 intr_enable() 함수를 호출하여 인터럽트를 활성화하고,
            그렇지 않으면 intr_disable() 함수를 호출하여 인터럽트를 비활성화합니다.*/
    return level == INTR_ON ? intr_enable() : intr_disable();
}

/* Enables interrupts and returns the previous interrupt status. */
enum intr_level
/* 인터럽트를 활성화하는 역할을 하며, 호출하기 전에 현재의 인터럽트 상태를 저장하고, 그 상태가 비활성화 상태인지 확인한 후 인터럽트를 활성화 */
intr_enable( void ) {
    enum intr_level old_level = intr_get_level();  // 현재의 인터럽트 레벨을 저장합니다. 이 값은 함수가 종료될 때 반환되어, 호출 전의 상태를 복원하는 데 사용
    ASSERT( !intr_context() );                     // 현재가 인터럽트 컨텍스트인지 확인

    /* Enable interrupts by setting the interrupt flag.

       See [IA32-v2b] "STI" and [IA32-v3a] 5.8.1 "Masking Maskable
       Hardware Interrupts". */
    asm volatile( "sti" );  // 어셈블리 명령어는 Interrupt Flag를 설정하여 마스크 가능한 인터럽트를 활성화

    return old_level;
}

/* Disables interrupts and returns the previous interrupt status. */
/* 시스템에서 인터럽트를 비활성화하는 역할 */
enum intr_level intr_disable( void ) {
    enum intr_level old_level = intr_get_level();

    /* Disable interrupts by clearing the interrupt flag.
       See [IA32-v2b] "CLI" and [IA32-v3a] 5.8.1 "Masking Maskable
       Hardware Interrupts". */
    asm volatile( "cli"
                  :
                  :
                  : "memory" );  // 어셈블리 명령어는 Interrupt Flag를 클리어하여 마스크 가능한 인터럽트를 비활성화

    return old_level;
}

/* Initializes the interrupt system. */
/* 시스템의 인터럽트 관리 구조를 초기화하는 역할 : 인터럽트 컨트롤러와 인터럽트 기술 디스크립터(IDT)를 초기화 */
void intr_init( void ) {
    int i;

    /* Initialize interrupt controller. */
    pic_init();  // Programmable Interrupt Controller (PIC)를 초기화

    /* Initialize IDT. */
    /*INTR_CNT 만큼의 루프를 돌며 IDT를 초기화합니다.
            make_intr_gate(&idt[i], intr_stubs[i], 0);:
            make_intr_gate 매크로를 호출하여 IDT의 각 엔트리를 설정합니다.
            첫 번째 인수는 초기화할 IDT 엔트리의 포인터, 두 번째 인수는 해당 인터럽트와 연결된 처리 함수,
            세 번째 인수는 DPL(Descriptor Privilege Level)입니다. 여기서는 0으로 설정되어, 최상위 권한을 의미합니다.
            intr_names[i] = "unknown";:
            각 인터럽트에 대한 이름을 "unknown"으로 초기화합니다. 이후 실제 인터럽트가 정의되면 이 값을 변경할 수 있습니다*/
    for ( i = 0; i < INTR_CNT; i++ ) {
        make_intr_gate( &idt[i], intr_stubs[i], 0 );
        intr_names[i] = "unknown";
    }

#ifdef USERPROG
    /* Load TSS. */
    ltr( SEL_TSS );
#endif

    /* Load IDT register. */
    /* lidt 명령어는 IDT(Interrupt Descriptor Table) 레지스터를 로드하여 CPU에게 인터럽트에 대한 정보를 제공합니다.
            idt_desc는 IDT의 크기와 주소를 포함하는 구조체입니다. 이 구조체는 시스템이 인터럽트를 처리할 수 있도록 설정된 IDT를 참조합니다.*/
    lidt( &idt_desc );

    /* Initialize intr_names. */
    intr_names[0] = "#DE Divide Error";
    intr_names[1] = "#DB Debug Exception";
    intr_names[2] = "NMI Interrupt";
    intr_names[3] = "#BP Breakpoint Exception";
    intr_names[4] = "#OF Overflow Exception";
    intr_names[5] = "#BR BOUND Range Exceeded Exception";
    intr_names[6] = "#UD Invalid Opcode Exception";
    intr_names[7] = "#NM Device Not Available Exception";
    intr_names[8] = "#DF Double Fault Exception";
    intr_names[9] = "Coprocessor Segment Overrun";
    intr_names[10] = "#TS Invalid TSS Exception";
    intr_names[11] = "#NP Segment Not Present";
    intr_names[12] = "#SS Stack Fault Exception";
    intr_names[13] = "#GP General Protection Exception";
    intr_names[14] = "#PF Page-Fault Exception";
    intr_names[16] = "#MF x87 FPU Floating-Point Error";
    intr_names[17] = "#AC Alignment Check Exception";
    intr_names[18] = "#MC Machine-Check Exception";
    intr_names[19] = "#XF SIMD Floating-Point Exception";
    /*  #DE Divide Error: 0으로 나누기를 시도할 때 발생합니다.
            #DB Debug Exception: 디버거가 설정한 중단점에 도달했을 때 발생합니다.
            NMI Interrupt: Non-Maskable Interrupt로, 일반적인 인터럽트를 무시할 수 없는 중요한 신호입니다.
            #BP Breakpoint Exception: 코드 실행 중 디버깅 중단점에 도달했을 때 발생합니다.
            #OF Overflow Exception: 연산 결과가 표현할 수 있는 범위를 초과했을 때 발생합니다.
            #BR BOUND Range Exceeded Exception: BOUND 명령이 설정된 범위를 초과할 때 발생합니다.
            #UD Invalid Opcode Exception: CPU가 알 수 없는 명령어를 만났을 때 발생합니다.
            #NM Device Not Available Exception: 사용할 수 없는 장치에 접근하려 할 때 발생합니다.
            #DF Double Fault Exception: 중첩된 예외가 발생했을 때 발생합니다.
            #TS Invalid TSS Exception: Task State Segment가 유효하지 않을 때 발생합니다.
            #NP Segment Not Present: 존재하지 않는 세그먼트에 접근할 때 발생합니다.
            #SS Stack Fault Exception: 스택이 부족할 때 발생합니다.
            #GP General Protection Exception: 일반적인 보호 위반이 발생했을 때 발생합니다.
            #PF Page-Fault Exception: 메모리에 접근하려 할 때 해당 페이지가 메모리에 없을 경우 발생합니다.
            #MF x87 FPU Floating-Point Error: 부동 소수점 연산에서 오류가 발생했을 때 발생합니다.
            #AC Alignment Check Exception: 데이터 정렬 문제가 발생했을 때 발생합니다.
            #MC Machine-Check Exception: 하드웨어 오류가 발생했을 때 발생합니다.
            #XF SIMD Floating-Point Exception: SIMD 부동 소수점 연산에서 오류가 발생했을 때 발생합니다.*/
}

/* Registers interrupt VEC_NO to invoke HANDLER with descriptor
   privilege level DPL.  Names the interrupt NAME for debugging
   purposes.  The interrupt handler will be invoked with
   interrupt status set to LEVEL. */
/* 특정 인터럽트 벡터에 대한 핸들러와 그에 관련된 정보를 설정 */
/*	uint8_t vec_no: 인터럽트 벡터 번호로, 이 번호를 통해 특정 인터럽트를 식별합니다.
             int dpl: Descriptor Privilege Level로, 해당 핸들러가 접근할 수 있는 권한 수준을 나타냅니다. 이 값은 0부터 3까지 설정할 수 있습니다.
             enum intr_level level: 인터럽트의 활성화 상태를 나타내는 열거형으로, INTR_ON 또는 INTR_OFF의 값을 가질 수 있습니다.
             intr_handler_func *handler: 등록할 핸들러 함수의 포인터입니다. 이 함수는 인터럽트가 발생했을 때 호출됩니다.
             const char *name: 인터럽트에 대한 설명 문자열입니다. 이 문자열은 디버깅 시 유용합니다.*/
static void register_handler( uint8_t vec_no, int dpl, enum intr_level level, intr_handler_func *handler, const char *name ) {
    ASSERT( intr_handlers[vec_no] == NULL );  // 해당 벡터 번호에 이미 핸들러가 등록되어 있지 않은지 확인
    if ( level == INTR_ON ) {
        make_trap_gate( &idt[vec_no], intr_stubs[vec_no], dpl );  // level이 INTR_ON인 경우, 트랩 게이트를 설정
    } else {
        make_intr_gate( &idt[vec_no], intr_stubs[vec_no], dpl );  // 일반 인터럽트 게이트를 설정
    }
    intr_handlers[vec_no] = handler;  // 지정된 인터럽트 벡터 번호에 대해 핸들러와 이름을 각각 저장
    intr_names[vec_no] = name;
}

/* Registers external interrupt VEC_NO to invoke HANDLER, which
   is named NAME for debugging purposes.  The handler will
   execute with interrupts disabled. */
/* 특정 인터럽트 벡터에 대한 외부 핸들러를 등록 */
/*   uint8_t vec_no: 등록할 인터럽트 벡터 번호로, 이 번호는 0x20에서 0x2f(32~47) 사이의 값을 가져야 합니다. 이 범위는 마스터 PIC에서 사용하는 IRQ 번호에 해당합니다.
             intr_handler_func *handler: 인터럽트가 발생했을 때 호출될 핸들러 함수의 포인터입니다.
             const char *name: 인터럽트에 대한 설명 문자열로, 디버깅이나 로깅 목적으로 사용됩니다. */
void intr_register_ext( uint8_t vec_no, intr_handler_func *handler, const char *name ) {
    ASSERT( vec_no >= 0x20 && vec_no <= 0x2f );              // vec_no가 0x20에서 0x2f(즉, 32에서 47) 사이에 있는지 확인합니다. 이 범위는 PIC(Priority Interrupt Controller)가 관리하는 외부 인터럽트를 나타냅니다
    register_handler( vec_no, 0, INTR_OFF, handler, name );  // register_handler 함수를 호출하여 핸들러를 등록
}

/* Registers internal interrupt VEC_NO to invoke HANDLER, which
   is named NAME for debugging purposes.  The interrupt handler
   will be invoked with interrupt status LEVEL.

   The handler will have descriptor privilege level DPL, meaning
   that it can be invoked intentionally when the processor is in
   the DPL or lower-numbered ring.  In practice, DPL==3 allows
   user mode to invoke the interrupts and DPL==0 prevents such
   invocation.  Faults and exceptions that occur in user mode
   still cause interrupts with DPL==0 to be invoked.  See
   [IA32-v3a] sections 4.5 "Privilege Levels" and 4.8.1.1
   "Accessing Nonconforming Code Segments" for further
   discussion. */
void intr_register_int( uint8_t vec_no, int dpl, enum intr_level level, intr_handler_func *handler, const char *name ) {
    ASSERT( vec_no < 0x20 || vec_no > 0x2f );
    register_handler( vec_no, dpl, level, handler, name );
}

/* Returns true during processing of an external interrupt
   and false at all other times. */
bool intr_context( void ) { return in_external_intr; }

/* During processing of an external interrupt, directs the
   interrupt handler to yield to a new process just before
   returning from the interrupt.  May not be called at any other
   time. */
void intr_yield_on_return( void ) {
    ASSERT( intr_context() );
    yield_on_return = true;
}

/* 8259A Programmable Interrupt Controller. */

/* Every PC has two 8259A Programmable Interrupt Controller (PIC)
   chips.  One is a "master" accessible at ports 0x20 and 0x21.
   The other is a "slave" cascaded onto the master's IRQ 2 line
   and accessible at ports 0xa0 and 0xa1.  Accesses to port 0x20
   set the A0 line to 0 and accesses to 0x21 set the A1 line to
   1.  The situation is similar for the slave PIC.

   By default, interrupts 0...15 delivered by the PICs will go to
   interrupt vectors 0...15.  Unfortunately, those vectors are
   also used for CPU traps and exceptions.  We reprogram the PICs
   so that interrupts 0...15 are delivered to interrupt vectors
   32...47 (0x20...0x2f) instead. */

/* Initializes the PICs.  Refer to [8259A] for details. */
/* 함수는 8259A Programmable Interrupt Controller (PIC)를 초기화하여 시스템의 인터럽트 처리 기능을 설정하는 역할 */
/* 마스터와 슬레이브 PIC를 설정하며, 각 인터럽트 소스에 대한 IRQ(Interrupt Request) 번호를 정의 */
static void pic_init( void ) {
    /* Mask all interrupts on both PICs. */
    /* 마스터 PIC(0x21)와 슬레이브 PIC(0xa1)의 모든 인터럽트를 마스킹합니다. 이로 인해 초기화 과정 중에 발생할 수 있는 인터럽트를 차단 */
    outb( 0x21, 0xff );
    outb( 0xa1, 0xff );

    /* Initialize master. */
    outb( 0x20, 0x11 ); /* ICW1: single mode, edge triggered, expect ICW4. */
    outb( 0x21, 0x20 ); /* ICW2: line IR0...7 -> irq 0x20...0x27. */
    outb( 0x21, 0x04 ); /* ICW3: slave PIC on line IR2. */
    outb( 0x21, 0x01 ); /* ICW4: 8086 mode, normal EOI, non-buffered. */

    /* Initialize slave. */
    outb( 0xa0, 0x11 ); /* ICW1: single mode, edge triggered, expect ICW4. */
    outb( 0xa1, 0x28 ); /* ICW2: line IR0...7 -> irq 0x28...0x2f. */
    outb( 0xa1, 0x02 ); /* ICW3: slave ID is 2. */
    outb( 0xa1, 0x01 ); /* ICW4: 8086 mode, normal EOI, non-buffered. */

    /* Unmask all interrupts. */
    outb( 0x21, 0x00 );
    outb( 0xa1, 0x00 );
}

/* Sends an end-of-interrupt signal to the PIC for the given IRQ.
   If we don't acknowledge the IRQ, it will never be delivered to
   us again, so this is important.  */
/* pic_end_of_interrupt 함수는 PIC(Programmable Interrupt Controller)에 인터럽트 처리 완료를 알리는 역할 */
static void pic_end_of_interrupt( int irq ) {
    ASSERT( irq >= 0x20 && irq < 0x30 );

    /* Acknowledge master PIC. */
    outb( 0x20, 0x20 );

    /* Acknowledge slave PIC if this is a slave interrupt. */
    if ( irq >= 0x28 ) outb( 0xa0, 0x20 );
}
/* Interrupt handlers. */

/* Handler for all interrupts, faults, and exceptions.  This
   function is called by the assembly language interrupt stubs in
   intr-stubs.S.  FRAME describes the interrupt and the
   interrupted thread's registers. */
/* 인터럽트 발생 시 호출되는 핸들러로, 특정 인터럽트에 대한 처리를 수행합니다.
이 함수는 외부 인터럽트를 처리하고, 해당 인터럽트에 등록된 핸들러를 호출하며, 인터럽트 처리 완료 후 PIC에 신호를 보냅니다. */
void intr_handler( struct intr_frame *frame ) {
    bool external;
    intr_handler_func *handler;

    /* External interrupts are special.
       We only handle one at a time (so interrupts must be off)
       and they need to be acknowledged on the PIC (see below).
       An external interrupt handler cannot sleep. */
    external = frame->vec_no >= 0x20 && frame->vec_no < 0x30;
    if ( external ) {
        ASSERT( intr_get_level() == INTR_OFF );
        ASSERT( !intr_context() );

        in_external_intr = true;
        yield_on_return = false;
    }

    /* Invoke the interrupt's handler. */
    handler = intr_handlers[frame->vec_no];
    if ( handler != NULL )
        handler( frame );
    else if ( frame->vec_no == 0x27 || frame->vec_no == 0x2f ) {
        /* There is no handler, but this interrupt can trigger
           spuriously due to a hardware fault or hardware race
           condition.  Ignore it. */
    } else {
        /* No handler and not spurious.  Invoke the unexpected
           interrupt handler. */
        intr_dump_frame( frame );
        PANIC( "Unexpected interrupt" );
    }

    /* Complete the processing of an external interrupt. */
    if ( external ) {
        ASSERT( intr_get_level() == INTR_OFF );
        ASSERT( intr_context() );

        in_external_intr = false;
        pic_end_of_interrupt( frame->vec_no );

        if ( yield_on_return ) thread_yield();
    }
}

/* Dumps interrupt frame F to the console, for debugging. */
/* 인터럽트가 발생했을 때, 현재 CPU의 레지스터 상태와 관련 정보를 출력하는 데 사용됩니다. 이 함수는 디버깅과 문제 해결을 위해 중요한 정보를 제공 */
void intr_dump_frame( const struct intr_frame *f ) {
    /* CR2 is the linear address of the last page fault.
       See [IA32-v2a] "MOV--Move to/from Control Registers" and
       [IA32-v3a] 5.14 "Interrupt 14--Page Fault Exception
       (#PF)". */
    uint64_t cr2 = rcr2();
    printf( "Interrupt %#04llx (%s) at rip=%llx\n", f->vec_no, intr_names[f->vec_no], f->rip );
    printf( " cr2=%016llx error=%16llx\n", cr2, f->error_code );
    printf( "rax %016llx rbx %016llx rcx %016llx rdx %016llx\n", f->R.rax, f->R.rbx, f->R.rcx, f->R.rdx );
    printf( "rsp %016llx rbp %016llx rsi %016llx rdi %016llx\n", f->rsp, f->R.rbp, f->R.rsi, f->R.rdi );
    printf( "rip %016llx r8 %016llx  r9 %016llx r10 %016llx\n", f->rip, f->R.r8, f->R.r9, f->R.r10 );
    printf( "r11 %016llx r12 %016llx r13 %016llx r14 %016llx\n", f->R.r11, f->R.r12, f->R.r13, f->R.r14 );
    printf( "r15 %016llx rflags %08llx\n", f->R.r15, f->eflags );
    printf( "es: %04x ds: %04x cs: %04x ss: %04x\n", f->es, f->ds, f->cs, f->ss );
}

/* Returns the name of interrupt VEC. */
/* 주어진 인터럽트 벡터 번호에 해당하는 인터럽트의 이름을 반환합니다. 이 함수는 인터럽트 처리 시스템에서 인터럽트의 의미를 이해하는 데 도움을 주는 간단한 유틸리티 */
const char *intr_name( uint8_t vec ) { return intr_names[vec]; }