#ifndef THREADS_INTERRUPT_H
#define THREADS_INTERRUPT_H

#include <stdbool.h>
#include <stdint.h>

/* Interrupts on or off? */
enum intr_level {
	INTR_OFF,             /* Interrupts disabled. */
	INTR_ON               /* Interrupts enabled. */
};

enum intr_level intr_get_level (void);
enum intr_level intr_set_level (enum intr_level);
enum intr_level intr_enable (void);
enum intr_level intr_disable (void);

/* Interrupt stack frame. */
struct gp_registers {
	uint64_t r15;
	uint64_t r14;
	uint64_t r13;
	uint64_t r12;
	uint64_t r11;
	uint64_t r10;
	uint64_t r9;
	uint64_t r8;
	uint64_t rsi;
	uint64_t rdi;
	uint64_t rbp;
	uint64_t rdx;
	uint64_t rcx;
	uint64_t rbx;
	uint64_t rax;
} __attribute__((packed));

struct intr_frame {
	/* intr-stubs.S의 intr_entry에서 저장됨.
	   이 값들은 인터럽트된 작업의 레지스터 상태를 저장하는 부분입니다. */
	struct gp_registers R;  // 일반 레지스터 저장
	uint16_t es;            // 세그먼트 레지스터 es
	uint16_t __pad1;        // 정렬을 맞추기 위한 패딩
	uint32_t __pad2;        // 정렬을 맞추기 위한 패딩
	uint16_t ds;            // 세그먼트 레지스터 ds
	uint16_t __pad3;        // 정렬을 맞추기 위한 패딩
	uint32_t __pad4;        // 정렬을 맞추기 위한 패딩
	
	/* intr-stubs.S의 intrNN_stub에서 저장됨. */
	uint64_t vec_no; /* 인터럽트 벡터 번호 (어떤 인터럽트가 발생했는지 나타냅니다.) */

	/* 종종 CPU에 의해 저장되며,
	   그렇지 않으면 intrNN_stub에서 일관성을 위해 0으로 설정됩니다.
	   CPU는 이 값을 `eip` 바로 아래에 두지만, 여기서는 이 위치로 옮깁니다. */
	uint64_t error_code;  // 에러 코드 (인터럽트 발생 시, 특정 상황에서 전달됨)

	/* CPU에 의해 저장됨.
	   이 값들은 인터럽트된 작업의 레지스터 상태를 저장하는 부분입니다. */
	uintptr_t rip;     // 명령어 포인터 레지스터 (프로그램 카운터) 저장 (인터럽트 발생 시 실행 중이던 명령어 주소)
	uint16_t cs;       // 코드 세그먼트 레지스터
	uint16_t __pad5;   // 정렬을 맞추기 위한 패딩
	uint32_t __pad6;   // 정렬을 맞추기 위한 패딩
	uint64_t eflags;   // 플래그 레지스터 저장 (CPU의 상태를 나타냄)
	uintptr_t rsp;     // 스택 포인터 레지스터 (인터럽트 당시의 스택 주소)
	uint16_t ss;       // 스택 세그먼트 레지스터
	uint16_t __pad7;   // 정렬을 맞추기 위한 패딩
	uint32_t __pad8;   // 정렬을 맞추기 위한 패딩
} __attribute__((packed));  // 메모리 패딩을 없애고 원하는 대로 정렬하는 속성

typedef void intr_handler_func (struct intr_frame *);

void intr_init (void);
void intr_register_ext (uint8_t vec, intr_handler_func *, const char *name);
void intr_register_int (uint8_t vec, int dpl, enum intr_level,
                        intr_handler_func *, const char *name);
bool intr_context (void);
void intr_yield_on_return (void);

void intr_dump_frame (const struct intr_frame *);
const char *intr_name (uint8_t vec);

#endif /* threads/interrupt.h */
