#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef VM
#include "vm/vm.h"
#endif

static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);

/* General process initializer for initd and other process. */
static void
process_init (void) {
	struct thread *current = thread_current ();
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t
process_create_initd (const char *file_name) {
	char *fn_copy;
	char *save_ptr;
	tid_t tid;

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy (fn_copy, file_name, PGSIZE);
	
	file_name = strtok_r(file_name, " ", &save_ptr);
	/* Create a new thread to execute FILE_NAME. */
	tid = thread_create (file_name, PRI_DEFAULT, initd, fn_copy);
	if (tid == TID_ERROR)
		palloc_free_page (fn_copy);
	return tid;
}

/* A thread function that launches first user process. */
static void
initd (void *f_name) {
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif

	process_init ();

	if (process_exec (f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED ();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t
process_fork (const char *name, struct intr_frame *if_ UNUSED) {
	/* Clone current thread to new thread.*/
	return thread_create (name,
			PRI_DEFAULT, __do_fork, thread_current ());
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
	struct thread *current = thread_current ();
	struct thread *parent = (struct thread *) aux;
	void *parent_page;
	void *newpage;
	bool writable;

	/* 1. TODO: If the parent_page is kernel page, then return immediately. */

	/* 2. Resolve VA from the parent's page map level 4. */
	parent_page = pml4_get_page (parent->pml4, va);

	/* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE. */

	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */

	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
		/* 6. TODO: if fail to insert page, do error handling. */
	}
	return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void
__do_fork (void *aux) {
	struct intr_frame if_;
	struct thread *parent = (struct thread *) aux;
	struct thread *current = thread_current ();
	/* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
	struct intr_frame *parent_if;
	bool succ = true;

	/* 1. Read the cpu context to local stack. */
	memcpy (&if_, parent_if, sizeof (struct intr_frame));

	/* 2. Duplicate PT */
	current->pml4 = pml4_create();
	if (current->pml4 == NULL)
		goto error;

	process_activate (current);
#ifdef VM
	supplemental_page_table_init (&current->spt);
	if (!supplemental_page_table_copy (&current->spt, &parent->spt))
		goto error;
#else
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent))
		goto error;
#endif

	/* TODO: Your code goes here.
	 * TODO: Hint) To duplicate the file object, use `file_duplicate`
	 * TODO:       in include/filesys/file.h. Note that parent should not return
	 * TODO:       from the fork() until this function successfully duplicates
	 * TODO:       the resources of parent.*/

	process_init ();

	/* Finally, switch to the newly created process. */
	if (succ)
		do_iret (&if_);
error:
	thread_exit ();
}

/* 현재 실행 중인 프로세스를 정리하고,
 * 주어진 실행 파일로 전환합니다.
 * 만약 파일 로드에 실패하면 -1을 반환하고 종료됩니다. */
int
process_exec (void *f_name) {
	char *file_name = f_name;  // `f_name`은 실행할 프로그램 파일 이름	
	bool success;  // 파일 로드 성공 여부를 저장할 변수

	char *token, *save_ptr, *argv[64];
	int argc = 0 ; 

	/* 현재 스레드 구조체의 intr_frame을 사용할 수 없습니다.
	 * 왜냐하면 스레드는 스케줄링마다 intr_frame에 값을 저장하기 때문에,
	 * 다른 함수에서 재사용하면 값이 꼬일 수 있습니다.
	 * 그래서 새로운 `intr_frame` 구조체를 선언하여 여기에 상태 정보를 담습니다. */
	struct intr_frame _if;  // 인터럽트 프레임: CPU 상태 정보 저장 (레지스터, 플래그 등)
	
	// 사용자 세그먼트 설정 (이 값들은 사용자 모드에서 실행되는 프로세스가 사용할 세그먼트)
	_if.ds = _if.es = _if.ss = SEL_UDSEG;  // 데이터 세그먼트 (사용자용)
	
	// 코드 세그먼트 설정 (사용자 모드에서 실행)
	_if.cs = SEL_UCSEG;  // 사용자 코드 세그먼트
	
	// CPU 플래그 설정: 인터럽트 허용 플래그(IF)와 시스템 필수 플래그(MBS)를 세팅
	_if.eflags = FLAG_IF | FLAG_MBS;  // 플래그 설정 (인터럽트 활성화와 필수값 세팅)

	/* 현재 실행 중인 프로세스를 정리합니다.
	 * 이는 해당 프로세스가 사용 중이던 메모리, 파일 디스크립터, 자원 등을 해제하고,
	 * 재사용할 수 있도록 돌려주는 작업입니다. */
	process_cleanup ();  // 현재 프로세스 정리 (메모리 및 자원을 해제)

	token = strtok_r(file_name, " ", &save_ptr);
	while(token != NULL){
		argv[argc++]=token;
		printf("--------------\n");
		printf("------%s-----\n",token);
		printf("--------------\n");
		token = strtok_r(NULL," ",&save_ptr);
	
	}



	/* 주어진 파일을 로드합니다.
	 * 화면에 보이는 `file_name`을 로드하는데,
	 * 이 과정에서 `_if` 구조체의 내용을 참고하여 CPU 상태 정보와 메모리 설정을 같이 만듭니다.
	 * 성공 시 `success = true`, 실패 시 `success = false`가 되며 결과에 따라 처리가 달라집니다. */
	success = load (file_name, &_if);  // 파일을 메모리에 로드하여 프로그램 준비

	
	// Argument Passing ~
	argument_stack(argv, argc, &_if); // 함수 내부에서 argv와 rsp의 값을 직접 변경하기 위해 주소 전달
    
	hex_dump(_if.rsp, _if.rsp, USER_STACK - (uint64_t)_if.rsp, true); // user stack을 16진수로 프린트
	// ~ Argument Passing

	/* 파일 로드가 실패했을 경우, 파일 이름으로 할당한 메모리를 해제하고 `-1`을 반환하여 종료합니다. */
	palloc_free_page (file_name);  // `file_name`이 가리키는 페이지(메모리)를 해제
	if (!success)
		return -1;  // 프로그램 로드가 실패하면 -1 반환 (프로세스 전환 실패)

	/* 로드가 정상적으로 끝났으면, 이제 `_if` 구조체에 저장된
	 * 새 프로세스로 전환하여 실행을 시작합니다.
	 * `do_iret()` 함수는 `_if`에 저장된 CPU 상태를 참고하여 컨텍스트를 전환합니다.
	 * 이 과정에서 새로 로드된 프로그램을 실행하게 됩니다. */
	do_iret (&_if);  // `do_iret`을 호출하여 새로운 프로세스 실행으로 전환
	NOT_REACHED();  // `do_iret`이 실행되면 새 프로그램으로 넘어가므로 이 코드는 실행되지 않아야 함 (여기 도달하면 논리 오류)
}
void argument_stack(char **argv, int argc, struct intr_frame *if_)
{
	char *arg_address[128];

	// 프로그램 이름, 인자 문자열 push
	for(int i = argc - 1; i >= 0; i--)
	{
		int arg_i_len = strlen(argv[i]) +1;	//sential(\0) 포함
		if_->rsp -= arg_i_len;			//인자 크기만큼 스택을 늘려줌
		memcpy(if_->rsp, argv[i], arg_i_len);	//늘려준 공간에 해당 인자를 복사
		arg_address[i] = (char *)if_->rsp;	//arg_address에 위 인자를 복사해준 주소값을 저장
	}

	// word-align(8의 배수)로 맞춰주기
	if(if_->rsp % 8 != 0)
	{	
		int padding = if_->rsp % 8;
		if_->rsp -= padding;
		memset(if_->rsp, 0, padding);
	}

	// 인자 문자열 종료를 나타내는 0 push
	if_->rsp -= 8; 	
	memset(if_->rsp, 0, 8);

	// 각 인자 문자열의 주소 push
	for(int i = argc-1; i >= 0; i--)
	{
		if_->rsp -= 8;
		memcpy(if_->rsp, &arg_address[i], 8);
	}

	// fake return address
	if_->rsp -= 8;
	memset(if_->rsp, 0, 8);

	//rdi 에는 인자의 개수, rsi에는 argv 첫 인자의 시작 주소 저장
	if_->R.rdi = argc;
	if_->R.rsi = if_->rsp + 8;	//fake return address + 8
}
/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int
process_wait (tid_t child_tid UNUSED) {
	/* XXX: Hint) The pintos exit if process_wait (initd), we recommend you
	 * XXX:       to add infinite loop here before
	 * XXX:       implementing the process_wait. */
	while(1){
	
	}
	return -1;
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
	struct thread *curr = thread_current ();
	/* TODO: Your code goes here.
	 * TODO: Implement process termination message (see
	 * TODO: project2/process_termination.html).
	 * TODO: We recommend you to implement process resource cleanup here. */

	process_cleanup ();
}

/* 종합적인 동작 과정
이 함수는 운영체제에서 프로세스가 끝날 때 수행되는 메모리 정리 작업입니다. 
페이지 테이블(프로세스의 메모리 관리 구조)을 삭제하고, 
가상 메모리 테이블을 포함해 필요한 모든 메모리 자원을 반환하는 역할을 합니다. */
static void
process_cleanup (void) {
    // 현재 실행 중인 스레드를 가져온다.
    struct thread *curr = thread_current ();

#ifdef VM
    // (가상 메모리가 활성화되어 있다면) 현재 스레드의 보조 페이지 테이블을 제거한다.
    // supplemental page table은 페이지 테이블의 추가/확장 버전으로 스와핑(디스크와 메모리 간 페이지 전환)을 처리하거나
    // 보조 메모리 시스템을 관리하는 구조체입니다.
    supplemental_page_table_kill (&curr->spt);
#endif

    uint64_t *pml4;  // 페이지 테이블을 가리키는 포인터입니다. (PML4는 x86-64 아키텍처에서 사용하는 4단계 페이지 테이블 중 가장 상위 레벨입니다.)

    /* 현재 프로세스의 페이지 디렉토리를 파괴하고
     * 커널 전용 페이지 디렉토리로 다시 전환합니다. */
    pml4 = curr->pml4;  // 현재 스레드의 페이지 테이블을 pml4 변수에 저장.
    if (pml4 != NULL) {
        /* 여기서의 처리 순서가 매우 중요합니다.
         * 타이머 인터럽트가 프로세스의 페이지 디렉토리로 다시 전환하지 않도록,
         * 페이지 디렉토리를 전환하기 전에 현재 스레드의 pml4를 NULL로 설정해야 합니다.
         *
         * 프로세스의 페이지 디렉토리를 파괴(해제)하기 전에
         * 기본 커널 전용 페이지 디렉토리로 전환해야 합니다.
         * 그렇지 않으면 현재 활성화된 페이지 디렉토리가 해제되었거나 삭제된 페이지 디렉토리가 될 수 있습니다. */
        curr->pml4 = NULL;  // 현재 스레드의 페이지 테이블을 NULL로 설정 (다른 페이지 테이블로 전환하지 않도록).
        pml4_activate (NULL);  // 커널 전용 페이지 테이블을 활성화. (NULL을 인자로 넘겨서 기본 페이지 테이블 설정).
        pml4_destroy (pml4);  // 기존 프로세스의 페이지 테이블(pml4)을 파괴(메모리 해제).
    }
}

/* 다음 스레드에서 사용자 코드를 실행하기 위해 CPU를 설정하는 함수.
 * 이 함수는 매번 컨텍스트 스위치가 발생할 때 호출됩니다. */
void
process_activate (struct thread *next) {
    /* 스레드의 페이지 테이블을 활성화.
       페이지 테이블은 프로세스의 가상 메모리와 실제 물리 메모리 간의 매핑을 관리하는 구조입니다.
       여기서는 다음에 실행될 스레드(`next`)의 페이지 테이블을 CPU에 활성화하여, 해당 스레드가
       올바른 메모리 주소에 접근할 수 있도록 합니다. */
    pml4_activate (next->pml4);

    /* 스레드의 커널 스택을 인터럽트 처리 중에 사용할 수 있도록 설정.
       커널 스택은 각 스레드마다 따로 할당되며, 이 스택은 인터럽트가 발생할 때
       커널 모드에서 처리할 데이터를 저장하는 데 사용됩니다. 
       `tss_update` 함수는 현재 스레드의 커널 스택 위치를 CPU의 TSS(Task State Segment)에 업데이트하여,
       인터럽트가 발생하면 이 스택을 사용할 수 있도록 합니다. */
    tss_update (next);
}
/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);
/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool
load (const char *file_name, struct intr_frame *if_) {
	// 현재 실행 중인 스레드 가져오기 (스레드는 프로세스와 동일)
	struct thread *t = thread_current ();
	
	// ELF 헤더와 파일 포인터 선언
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;  // 파일 오프셋(위치)를 저장하기 위한 변수
	bool success = false;  // 파일 로드가 성공했는지 여부를 저장하는 변수
	int i;  // 반복문에서 쓰일 변수

	/* 페이지 테이블(pml4)을 생성하고 활성화합니다. */
	t->pml4 = pml4_create ();  // 새로운 페이지 맵 레벨 4 테이블 생성 (가상 메모리 맵핑을 위한)
	if (t->pml4 == NULL)  // 페이지 테이블 생성이 실패하면 프로그램 로드를 실패로 처리
		goto done;
	process_activate (thread_current ());  // 새로운 페이지 테이블 활성화 (새 페이지 디렉토리를 CPU에 로드)

	/* 실행 파일을 엽니다. */
	file = filesys_open (file_name);  // 주어진 파일 이름으로 실행 파일을 엽니다.
	if (file == NULL) {  // 파일이 없거나 열기에 실패한 경우
		printf ("load: %s: open failed\n", file_name);
		goto done;
	}

	/* ELF 헤더를 읽고 검증합니다. (정상적인 ELF 실행 파일인지 확인) */
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr  // ELF 헤더 크기 만큼 읽기
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)     // 첫 7바이트로 ELF 매직넘버 확인
			|| ehdr.e_type != 2  // 실행 파일 타입 체크 (ET_EXEC 타입)
			|| ehdr.e_machine != 0x3E  // 아키텍처 확인 (0x3E = x86-64)
			|| ehdr.e_version != 1  // ELF 버전 검증
			|| ehdr.e_phentsize != sizeof (struct Phdr)  // 프로그램 헤더 엔트리 크기 확인
			|| ehdr.e_phnum > 1024) {  // 프로그램 헤더의 수가 합리적인 범위인지 확인
		printf ("load: %s: error loading executable\n", file_name);
		goto done;  // 검사 중 하나라도 실패하면 `done`으로 이동해 종료
	}

	/* 프로그램 헤더 전체를 순회하며 메모리에 적재합니다. */
	file_ofs = ehdr.e_phoff;  // 프로그램 헤더가 시작되는 파일 내부 오프셋을 가져옴
	for (i = 0; i < ehdr.e_phnum; i++) {  // 각 프로그램 헤더를 하나씩 읽어서 처리
		struct Phdr phdr;  // 프로그램 헤더 구조체 선언

		// 파일 위치가 올바른지 확인
		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;
		file_seek (file, file_ofs);  // 파일에서 프로그램 헤더가 위치한 곳으로 이동

		// 하나의 프로그램 헤더를 읽기
		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;  // 다음 헤더로 이동하기 위해 오프셋을 증가

		// 프로그램 헤더의 종류에 따라 처리
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				/* 무시할 섹션 */
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				goto done;  // 지원하지 않는 프로그램 헤더
			case PT_LOAD:
				// 로드 가능 세그먼트인 경우 실행
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;  // 쓰기가 가능한지 확인
					// 해당 세그먼트가 파일 상에 존재하는 페이지와 메모리 상 페이지 위치 계산
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					uint32_t read_bytes, zero_bytes;

					if (phdr.p_filesz > 0) {
						/* 일반적인 세그먼트:
						 * 파일에서 읽어야 할 바이트와 남은 영역을 0으로 채움 */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						/* 파일에 존재하지 않는 메모리.
						 * 즉, 0으로 초기화. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					// 세그먼트를 메모리에 적재
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable))
						goto done;
				} else {
					goto done;  // 세그먼트가 유효하지 않으면 종료
				}
				break;
		}
	}

	/* 스택을 설정합니다. */
	if (!setup_stack (if_))  // 초기 스택을 설정하는 함수 호출
		goto done;

	/* 프로그램의 진입점(시작 주소)을 설정합니다. */
	if_->rip = ehdr.e_entry;  // 실행을 시작할 주소(RIP 레지스터에 해당)를 설정

	/* TODO: 이 부분에는 프로그램 인자 전달 등의 작업을 추가해야 합니다. */
	/* TODO: argument passing 구현은 여기에 추가될 것입니다. */

	success = true;  // 모든 과정이 문제없이 완료되었을 경우 성공으로 설정

done:
	/* 파일을 닫고, 성공 여부에 상관없이 메모리를 정리하고 반환합니다.  */
	file_close (file);  // 열린 파일 객체 해제
	return success;  // 성공 여부 반환
}


/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			printf("fail\n");
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page (kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool
lazy_load_segment (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		void *aux = NULL;
		if (!vm_alloc_page_with_initializer (VM_ANON, upage,
					writable, lazy_load_segment, aux))
			return false;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack (struct intr_frame *if_) {
	bool success = false;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */

	return success;
}
#endif /* VM */
