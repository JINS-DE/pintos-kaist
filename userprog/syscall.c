#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>

#include "threads/palloc.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

#include "include/userprog/process.h"
#include "include/filesys/inode.h"
#include "include/filesys/directory.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/synch.h"
#include "lib/string.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);
void check_address(void *addr);
void halt(void);
void exit(int status);
int fork(const char *thread_name, struct intr_frame *f);
int wait(int pid);
void close(int fd);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);

struct lock filesys_lock;

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

const int STDIN = 1;
const int STDOUT = 2;

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

	lock_init(&filesys_lock);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED)
{
	// TODO: Your implementation goes here.
	int sys_number = f->R.rax;
	switch (sys_number)
	{

	case SYS_HALT: /* Halt the operating system. */
		halt();
		break;

	case SYS_EXIT: /* Terminate this process. */
		exit(f->R.rdi);
		break;

	case SYS_FORK: /* Clone current process. */
		f->R.rax = fork(f->R.rdi, f);
		break;

	case SYS_EXEC: /* Switch current process. */
		exec(f->R.rdi) == -1;
		break;

	case SYS_WAIT: /* Wait for a child process to die. */
		f->R.rax = wait(f->R.rdi);
		break;

	case SYS_CREATE: /* Create a file. */
		f->R.rax = create(f->R.rdi, f->R.rsi);
		break;

	case SYS_REMOVE: /* Delete a file. */
		f->R.rax = remove(f->R.rdi);
		break;

	case SYS_OPEN: /* Open a file. */
		f->R.rax = open(f->R.rdi);
		break;

	case SYS_FILESIZE: /* Obtain a file's size. */
		f->R.rax = filesize(f->R.rdi);
		break;

	case SYS_READ: /* Read from a file. */
		f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
		break;

	case SYS_WRITE: /* Write to a file. */
		f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
		break;

	case SYS_SEEK: /* Change position in a file. */
		seek(f->R.rdi, f->R.rsi);
		break;

	case SYS_TELL: /* Report current position in a file. */
		f->R.rax = tell(f->R.rdi);
		break;

	case SYS_CLOSE: /* Close a file. */
		close(f->R.rdi);
		break;

	default:
		// printf ("system call!\n");
		// thread_exit ();
		exit(-1);
		break;
	}
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

int exec(char *cmd_line)
{
	// cmd_line이 유효한 사용자 주소인지 확인 -> 잘못된 주소인 경우 종료/예외 발생
	check_address(cmd_line);

	// process.c 파일의 process_create_initd 함수와 유사하다.
	// 단, 스레드를 새로 생성하는 건 fork에서 수행하므로
	// exec는 이미 존재하는 프로세스의 컨텍스트를 교체하는 작업을 하므로
	// 현재 프로세스의 주소 공간을 교체하여 새로운 프로그램을 실행
	// 이 함수에서는 새 스레드를 생성하지 않고 process_exec을 호출한다.

	// process_exec 함수 안에서 filename을 변경해야 하므로
	// 커널 메모리 공간에 cmd_line의 복사본을 만든다.
	// (현재는 const char* 형식이기 때문에 수정할 수 없다.)
	char *cmd_line_copy;
	cmd_line_copy = palloc_get_page(PAL_ZERO);
	if (cmd_line_copy == NULL)
		exit(-1);							  // 메모리 할당 실패 시 status -1로 종료한다.
	strlcpy(cmd_line_copy, cmd_line, PGSIZE); // cmd_line을 복사한다.

	// 스레드의 이름을 변경하지 않고 바로 실행한다.
	if (process_exec(cmd_line_copy) == -1)
		exit(-1); // 실패 시 status -1로 종료한다.
}

/**
 * 파일 생성 삭제 시 다음도 고려하면 좋을거 같다.
 * 파일 중복: 이미 존재하는 파일과 같은 이름으로 파일을 생성 불가
 * 파일이 존재하지 않음: 삭제하려는 파일이 존재하지 않을 때 삭제 불가
 * 프로세스가 파일을 열고 있는 경우 : 이경우에도 삭제되어야 한다.
 */

bool create(const char *file_created, unsigned initial_size)
{
	lock_acquire(&filesys_lock);
	check_address(file_created);
	bool success = filesys_create(file_created, initial_size);
	lock_release(&filesys_lock);
	return success;
}

bool remove(const char *file_removed)
{
	// 파일이름 유효한지 판단
	if (file_removed == NULL || strlen(file_removed) == 0)
	{
		return false; // 유효하지 않은 파일 이름 처리
	}

	struct dir *dir = dir_open_root();				 // 루트 디렉터리 열기
	bool success = dir != NULL						 // 루트 디렉터리를 제대로 열었는지 확인
				   && dir_remove(dir, file_removed); // 디렉터리에서 파일 제거

	dir_close(dir); // 디렉터리 닫기
	return success;
}

int open(const char *file_opened)
{
	// 파일이름 유효한지 판단
	if (file_opened == NULL || strlen(file_opened) == 0)
	{
		return -1; // 유효하지 않은 파일 이름일 경우
	}
	// 파일 열기 시도
	struct file *cur_file = filesys_open(file_opened);
	if (cur_file == NULL)
	{
		return -1; // 파일을 열지 못했을 경우
	}
	// 현재 스레드의 파일 디스크립터 테이블에 파일 추가
	struct thread *cur = thread_current();
	int fd = process_add_file(cur_file);
	if (fd == -1)
	{
		file_close(cur_file); // 파일 디스크립터 할당에 실패하면 파일을 닫음
	}
	return fd;
}

int filesize(int fd)
{
	struct file *cur_file = process_get_file(fd);
	if (cur_file == NULL)
	{
		return -1;
	}
	return file_length(cur_file);
}

void close(int fd)
{
	process_close_file(fd);
}

int read(int fd, void *buffer, unsigned size)
{
	check_address(buffer);

	char *ptr = (char *)buffer;
	int bytes_read = 0;

	lock_acquire(&filesys_lock);
	if (fd == STDIN_FILENO)
	{
		for (int i = 0; i < size; i++)
		{
			*ptr++ = input_getc();
			bytes_read++;
		}
		lock_release(&filesys_lock);
	}
	else
	{
		if (fd < 2)
		{

			lock_release(&filesys_lock);
			return -1;
		}
		struct file *file = process_get_file(fd);
		if (file == NULL)
		{

			lock_release(&filesys_lock);
			return -1;
		}
		// struct page *page = spt_find_page(&thread_current()->spt, buffer);
		// if (page && !page->writable)
		// {
		// 	lock_release(&filesys_lock);
		// 	exit(-1);
		// }
		bytes_read = file_read(file, buffer, size);
		lock_release(&filesys_lock);
	}
	return bytes_read;
}

int write(int fd, void *buffer, unsigned size)
{
	check_address(buffer);
	int bytes_write = 0;
	if (fd == STDOUT_FILENO)
	{
		putbuf(buffer, size);
		bytes_write = size;
	}
	else
	{
		if (fd < 2)
			return -1;
		struct file *file = process_get_file(fd);
		if (file == NULL)
			return -1;
		lock_acquire(&filesys_lock);
		bytes_write = file_write(file, buffer, size);
		lock_release(&filesys_lock);
	}
	return bytes_write;
}

void seek(int fd, unsigned position)
{
	struct file *file = process_get_file(fd);
	if (file != NULL)
	{
		file_seek(file, position);
	}
}

unsigned
tell(int fd)
{
	struct file *file = process_get_file(fd);
	file_tell(&file);
}

void check_address(void *addr)
{

	if (addr == NULL || !is_user_vaddr(addr))
	{
		//  printf("Invalid address: %p\n", addr);
		exit(-1);
	}
}