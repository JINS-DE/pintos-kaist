#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>

#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

#include "include/userprog/process.h"
#include "include/filesys/inode.h"
#include "include/filesys/directory.h"
#include "filesys/file.h"
#include "synch.h"

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
int read (int fd, void *buffer, unsigned size);
int write (int fd, void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
struct lock file_lock;

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
		f->R.rax = exec(f->R.rdi); /* Switch current process. */
		break;
	case SYS_CREATE:
		const char *file_created = (const char *)f->R.rdi;
		unsigned initial_size = f->R.rsi;
		f->R.rax = create(file_created, initial_size);
		break;
	case SYS_REMOVE:
		const char *file_removed = (const char *)f->R.rdi;
		f->R.rax = remove(file_removed);
		break;
	case SYS_OPEN:
		const char *file_opened = (const char *)f->R.rdi;
		f->R.rax = open(file_opened);
		break;
	case SYS_FILESIZE:
		int fd_size = (int)f->R.rdi;
		f->R.rax = filesize(fd_size);
		break;
	case SYS_READ:
		read(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_WRITE:
		write(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_SEEK:
		seek(f->R.rdi, f->R.rsi);
		break;
	case SYS_TELL:
		tell(f->R.rdi);
		break;
	case SYS_CLOSE:
		int fd_close = (int)f->R.rdi;
		break;
	default:
	{
		printf("Invaild system call number. \n");
		exit(-1);
		break;
	}
	/* 위 함수의 결과는 rax에 저장되어야 함 */
	// f->R.rax = result;
	thread_exit();
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

int exec(char *cmd_line){
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
	cmd_line_copy = palloc_get_page(0);
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
	// 파일이름 유효한지 판단
	if (file_created == NULL || strlen(file_created) == 0)
	{
		return false;
	}

	struct dir *dir = dir_open_root(); // 루트 디렉터리를 연다.
	disk_sector_t inode_sector = 0;	   // 저장할 inode의 섹터 번호

	// inode : 파일의 메타데이터가 저장되는 곳
	bool success = dir != NULL									// 루트 디렉터리를 제대로 열었는지 확인
				   && free_map_allocate(1, &inode_sector)		// 섹터 할당이 제대로 되었는지 확인
				   && inode_create(inode_sector, initial_size); // inode를 잘 만들었는지 확인

	if (success)
	{
		dir_add(dir, file_created, initial_size); // 디렉터리에 파일 추가
	}

	dir_close(dir); // 디렉터리 닫기
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

int read (int fd, void *buffer, unsigned size)
 {
	struct thread *curr = thread_current();
	struct file *file = curr->fdt[fd];
	int file_bytes;
	if(fd < 0 || fd >= MAX_FD){
		return -1;
	}

	if(file_bytes < 0){
		return -1;
	}

	if (fd == 0) {
		for(unsigned i = 0; i < size; i++)
		{
			((uint8_t *)buffer)[i] = input_getc();
		}

		file_bytes = size;
	} else if(fd >= 2){
		lock_acquire(&file_lock);
		file_bytes = (int)file_read(file, buffer, size);
		lock_release(&file_lock);
	} else if (fd == 1){
		return -1;
	}
	//todo fd = 1인경우?
	return file_bytes;
	

 /* 파일에 동시 접근이 일어날 수 있으므로 Lock 사용 */
 /* 파일 디스크립터를 이용하여 파일 객체 검색 */
 /* 파일 디스크립터가 0일 경우 키보드에 입력을 버퍼에 저장 후
버퍼의 저장한 크기를 리턴 (input_getc() 이용) */
 /* 파일 디스크립터가 0이 아닐 경우 파일의 데이터를 크기만큼 저
장 후 읽은 바이트 수를 리턴 */
 }

 int
write (int fd, void *buffer, unsigned size){
 {
	struct thread *curr = thread_current();
	struct file *file = curr->fdt[fd];
	int file_bytes;
	if(fd < 0 || fd >= MAX_FD){
		return -1;
	}

	if(file_bytes < 0){
		return -1;
	}

	if (fd == 0) {
		return -1;
	} else if (fd == 1){
		for(unsigned i = 0; i < size; i++)
	{
		putbuf(&buffer, (size_t)size);
	}	
	file_bytes = size;
	} else if(fd >= 2){
		lock_acquire(&file_lock);
		file_bytes = (int)file_write(file, buffer, size);
		lock_release(&file_lock);
	} 
	return file_bytes;
}
}
void 
seek(int fd, unsigned position){
	struct file *file = process_get_file(fd);
	file_seek(&file, position);
}

unsigned 
tell (int fd){
	struct file *file = process_get_file(fd);
	file_tell(&file);
}

// void check_address(void *addr)
// {
// 	if (addr == NULL || !is_user_vaddr(addr))
// 	{
// 		exit(-1);
// 	}
// }