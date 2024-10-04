#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	int syscall_no = f->R.rax;

    // switch (syscall_no) {
    //     case SYS_HALT:      // 시스템 종료
    //         halt();
    //         break;
    //     case SYS_EXIT:      // 프로세스 종료
    //         exit(f->R.rdi); // %rdi에 담긴 status 인수 사용
    //         break;
    //     case SYS_EXEC:      // 새로운 프로세스 실행
    //         exec(f->R.rdi); // %rdi에 담긴 cmd_line 인수 사용
    //         break;
    //     // 이후 추가적인 시스템 호출들에 대한 case
    //     default:
    //         printf("Unknown system call: %d\n", syscall_no);
    //         thread_exit();  // 알 수 없는 시스템 호출일 경우 종료
    }
}

// void halt(){
// 	power_off();
// }

// void check_address(void *addr) {
// 	struct thread *t = thread_current();
// 	/* --- Project 2: User memory access --- */
// 	// if (!is_user_vaddr(addr)||addr == NULL) 
// 	//-> 이 경우는 유저 주소 영역 내에서도 할당되지 않는 공간 가리키는 것을 체크하지 않음. 그래서 
// 	// pml4_get_page를 추가해줘야!
// 	if (!is_user_vaddr(addr)||addr == NULL||
// 	pml4_get_page(t->pml4, addr)== NULL)
// 	{
// 		exit(-1);
// 	}
// }
// void get_argument(void *esp, int *arg , int count)
// {
// /* 유저 스택에 저장된 인자값들을 커널로 저장 */
// /* 인자가 저장된 위치가 유저영역인지 확인 */
// }