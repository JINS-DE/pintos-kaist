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
void halt(void);
void exit(int status);
int fork(const char *thread_name, struct intr_frame *f);
int wait(int pid);
void close(int fd);
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

	switch (syscall_number)
	{
	case SYS_FORK:
		f->R.rax = fork(f->R.rdi, f);
		break;
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(f->R.rdi);
		break;
	case SYS_WAIT:
		f->R.rax = wait(f->R.rdi);
		break;
	case SYS_EXEC:
		// f->R.rax = exec(f->R.rdi); /* Switch current process. */
		break;
	case SYS_CLOSE:
		int fd_close = (int)f->R.rdi;
		break;
	}

	// TODO: Your implementation goes here.

	printf("system call!\n");
	thread_exit();
}
void close(int fd)
{
	process_close_file(fd);
}
int wait(int pid)
{
	return process_wait(pid);
}
int fork(const char *thread_name, struct intr_frame *f)
{
	return process_fork(thread_name, f);
}
void halt(void)
{
	power_off();
}
void exit(int status)
{
	/* 실행중인 스레드 구조체를 가져옴 */
	struct thread *current = thread_current();
	current->exit_status = status;
	/* 프로세스 종료 메시지 출력,
	출력 양식: “프로세스이름 : exit(종료상태 )” */
	printf("%s: exit(%d)\n", current->name, status);
	/* 스레드 종료 */
	thread_exit();
}

void check_address(void *addr)
{
	if (addr == NULL || !is_user_vaddr(addr))
	{
		exit(-1);
	}
}