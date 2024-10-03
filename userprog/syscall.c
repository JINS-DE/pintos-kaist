#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>

#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);
void check_address(void *addr);
/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081			/* Segment selector msr */
#define MSR_LSTAR 0xc0000082		/* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void syscall_init(void)
{
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
							((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			  FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED)
{	
	// 시스템 콜 번호를 %rax에서 가져옴
    int syscall_number = f->R.rax;

	/* 인자로 포인터가 넘어오는 경우는 커널 메모리 침범하지 않는지 검사해야하는듯...? */
	/* 파일 조작의 경우 lock을 거는 것도 고려하여야 함*/
    switch (syscall_number)
    {
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:
			// exit(f->R.rdi);
			break;
		case SYS_FORK:
			// fork()
			break;
		case SYS_EXEC:
			// exec()
			break;
		case SYS_WAIT:
			// wait()
			break;
		case SYS_CREATE:
			// create()
			break;
		case SYS_REMOVE:
			// remove();
			break;
		case SYS_OPEN:
			// open()
			break;
		case SYS_FILESIZE:
			// filesize()
			break;
		case SYS_READ:
			// read()
			break;
		case SYS_WRITE:
			// write()
			break;
		case SYS_SEEK:
			// seek()
			break;
		case SYS_TELL:
			// tell()
			break;
		case SYS_CLOSE:
			// close()
			break;
		default:
			//exit(-1);
			break;	
    }
	/* 위 함수의 결과는 rax에 저장되어야 함 */
	//f->R.rax = result;
	thread_exit();
}

void halt(void)
{
    power_off();
}

// void check_address(void *addr)
// {
// 	if (addr == NULL || !is_user_vaddr(addr))
// 	{
// 		exit(-1);
// 	}
// }