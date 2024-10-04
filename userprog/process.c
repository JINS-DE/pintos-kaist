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

static void process_cleanup(void);
static bool load(const char *file_name, struct intr_frame *if_);
static void initd(void *f_name);
static void __do_fork(void *);
struct thread *get_child_process(int pid);

/* initd와 다른 프로세스를 위한 일반적인 프로세스 초기화 함수 */
static void
process_init(void)
{
	struct thread *current = thread_current();
}
struct file *process_get_file(int fd)
{
	struct thread *cur_t = thread_current();

	if (cur_t->fdt[fd] != NULL)
	{
		return cur_t->fdt[fd];
	}
	else
	{
		return NULL;
	}
}

/* "initd"라는 첫 번째 사용자 프로그램을 FILE_NAME에서 로드하여 시작합니다.
 * 새 스레드는 process_create_initd()가 반환되기 전에 스케줄링될 수 있으며,
 * 심지어 종료될 수도 있습니다. initd의 스레드 ID를 반환하거나, 스레드를
 * 생성할 수 없으면 TID_ERROR를 반환합니다.
 * 주의: 이 함수는 한 번만 호출되어야 합니다. */
tid_t process_create_initd(const char *file_name)
{
	char *fn_copy;
	tid_t tid;

	/* FILE_NAME의 복사본을 만듭니다.
	 * 그렇지 않으면 호출자와 load() 사이에 경쟁 조건이 발생할 수 있습니다. */
	fn_copy = palloc_get_page(0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy(fn_copy, file_name, PGSIZE);

	// Argument Passing ~
    char *save_ptr;
    strtok_r(file_name, " ", &save_ptr);
    // ~ Argument Passing

	/* FILE_NAME을 실행하는 새로운 스레드를 생성합니다. */
	tid = thread_create(file_name, PRI_DEFAULT, initd, fn_copy);
	if (tid == TID_ERROR)
		palloc_free_page(fn_copy);
	return tid;
}
/* 첫 번째 사용자 프로세스를 시작하는 스레드 함수 */
static void
initd(void *f_name)
{
#ifdef VM
	supplemental_page_table_init(&thread_current()->spt);
#endif

	process_init();

	if (process_exec(f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED();
}
/* 현재 프로세스를 `name`으로 복제합니다. 새 프로세스의 스레드 ID를 반환하거나,
 * 스레드를 생성할 수 없으면 TID_ERROR를 반환합니다. */
tid_t process_fork(const char *name, struct intr_frame *if_ UNUSED)
{
	struct thread *cur = thread_current();
	memcpy(&cur->parent_if, if_, sizeof(struct intr_frame));
	/* 현재 스레드를 새로운 스레드로 복제합니다. */
	tid_t pid = thread_create(name, PRI_DEFAULT, __do_fork, cur);
	if (pid == TID_ERROR)
		return TID_ERROR;
	// 자식이 로드될 때까지 대기하기 위해서 방금 생성한 자식 스레드를 찾는다.
	struct thread *child = get_child_process(pid);

	sema_down(&child->load_sema);

	return pid;
}
// tid는 단순히 스레드의 ID일 뿐이고,
// 실제로 해당 스레드의 데이터(예: 세마포어,
// 스택 프레임 등)에 접근하려면 그 스레드의 구조체 포인터가 필요합니다.
// 그래서 get_child_process()를 통해 자식 스레드의 구조체를 찾는 과정
struct thread *get_child_process(int pid)
{
	struct thread *cur = thread_current();
	struct list *child_list = &cur->child_list;
	for (struct list_elem *e = list_begin(child_list); e != list_end(child_list); e = list_next(e))
	{
		struct thread *t = list_entry(e, struct thread, child_elem);
		if (t->tid == pid)
		{
			return t;
		}
	}
	return NULL;
}

#ifndef VM
/* 부모의 주소 공간을 pml4_for_each 함수에 전달하여 복제합니다.
 * 이는 프로젝트 2에만 해당됩니다. */
static bool
duplicate_pte(uint64_t *pte, void *va, void *aux)
{
	struct thread *current = thread_current();
	struct thread *parent = (struct thread *)aux;
	void *parent_page;
	void *newpage;
	bool writable;

	/* 1. TODO: parent_page가 커널 페이지인 경우 즉시 반환합니다. */
	if (is_kernel_vaddr(va))
		return true;
	/* 2. 부모의 페이지 맵 레벨 4에서 VA를 해석합니다. */
	parent_page = pml4_get_page(parent->pml4, va);
	if (parent_page == NULL)
		return false;
	/* 3. TODO: 자식에게 새로운 PAL_USER 페이지를 할당하고,
	 *    TODO: NEWPAGE에 결과를 설정합니다. */
	newpage = palloc_get_page(PAL_USER | PAL_ZERO);
	if (newpage == NULL)
		return false;
	/* 4. TODO: 부모의 페이지를 새로운 페이지로 복사하고,
	 *    TODO: 부모의 페이지가 쓰기 가능한지 확인합니다
	 *    TODO: (결과에 따라 WRITABLE을 설정합니다). */
	memcpy(newpage, parent_page, PGSIZE);
	writable = is_writable(pte);
	/* 5. 자식의 페이지 테이블에 주소 VA로 WRITABLE 권한을 가진 새로운 페이지를 추가합니다. */
	if (!pml4_set_page(current->pml4, va, newpage, writable))
	{
		/* 6. TODO: 페이지 삽입에 실패한 경우, 오류 처리를 수행합니다. */
		return false;
	}
	return true;
}
#endif
/* 부모의 실행 컨텍스트를 복사하는 스레드 함수
 * 힌트) parent->tf는 프로세스의 사용자 영역 컨텍스트를 포함하지 않습니다.
 *       즉, process_fork의 두 번째 인자를 이 함수에 전달해야 합니다. */
static void
__do_fork(void *aux)
{
	struct intr_frame if_;
	struct thread *parent = (struct thread *)aux;
	struct thread *current = thread_current();
	/* TODO: 어떻게든 parent_if를 전달합니다 (예: process_fork()의 if_) */
	struct intr_frame *parent_if = &parent->parent_if;
	bool succ = true;

	/* 1. CPU 컨텍스트를 로컬 스택으로 읽어옵니다. */
	memcpy(&if_, parent_if, sizeof(struct intr_frame));
	// 자식 프로세스의 리턴값은 0으로 지정한다.
	if_.R.rax = 0;

	/* 2. 페이지 테이블 복제 */
	current->pml4 = pml4_create();
	if (current->pml4 == NULL)
		goto error;

	process_activate(current);
#ifdef VM
	supplemental_page_table_init(&current->spt);
	if (!supplemental_page_table_copy(&current->spt, &parent->spt))
		goto error;
#else
	if (!pml4_for_each(parent->pml4, duplicate_pte, parent))
		goto error;
#endif

	/* TODO: 여기에 코드 작성
	 * TODO: 힌트) 파일 객체를 복제하려면 include/filesys/file.h의 `file_duplicate`를 사용하세요.
	 * TODO: 부모가 자원의 복제를 성공적으로 마칠 때까지 fork()에서 반환하면 안 됩니다. */

	for (int i = 0; i < FDT_COUNT_LIMIT; i++)
	{
		struct file *file = parent->fdt[i];
		if (file == NULL)
			continue;
		if (file > 2)
			file = file_duplicate(file);
		current->fdt[i] = file;
	}

	current->next_fd = parent->next_fd;
	sema_up(&current->load_sema);
	process_init();

	/* 마지막으로 새로 생성된 프로세스로 전환합니다. */
	if (succ)
		do_iret(&if_);
error:
	sema_up(&current->load_sema);
	thread_exit();
}
/* f_name으로 현재 실행 컨텍스트를 전환합니다.
 * 실패 시 -1을 반환합니다. */
int process_exec(void *f_name)
{
	char *file_name = f_name;
	bool success;

	/* 스레드 구조의 intr_frame을 사용할 수 없습니다.
	 * 이는 현재 스레드가 다시 스케줄링될 때 실행 정보를 해당 멤버에 저장하기 때문입니다. */
	// intr_frame을 초기화한다.
	// 인터럽트 프레임 : CPU의 상태를 저장하는 구조체로 인터럽트가 발생했을 때, 새로운 프로세스를 시작할 때 사용
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG; // 데이터 세그먼트(ds), 엑스트라 세그먼트(es) 스택 세그먼트(ss)를 사용자 데이터 세그먼트로 설정
	_if.cs = SEL_UCSEG;					  // 코드 세그먼트(cs)를 사용자 코드 세그먼트로 설정
	_if.eflags = FLAG_IF | FLAG_MBS;	  // 인터럽트를 활성화 하는 플래그(FLAG_IF), 필수 플래그(FLAG_MBS) 설정

	/* We first kill the current context */
	// 현재 실행 중 프로세스의 주소공간 & 관련 자원들을 정리한다.
	// 현재 프로세스가 사용 중인 메모리 등을 해제한다.
	process_cleanup();

	/* And then load the binary */
	// file_name을 메모리에 로드한다.
	// _if에 필요한 정보를 저장한다.
	// 성공시 true를 반환한다.
	success = load(file_name, &_if);

	// hex_dump(_if.rsp, _if.rsp, USER_STACK - (uint64_t)_if.rsp, true); // user stack을 16진수로 프린트

	/* If load failed, quit. */
	palloc_free_page(file_name);
	if (!success)
		return -1;

	/* Start switched process. */
	// 새 프로세스를 시작한다.
	// 인터럽트 리턴을 통해, 저장된 _if를 사용해 CPU 상태를 복구한다.
	// 사용자 모드에서 새 프로그램의 실행을 시작한다.
	// 이 함수가 호출되면, 현재 스레드는 새 프로그램을 실행하는 상태로 전환된다.
	// printf(" b4 call do_iret !!!");
	do_iret(&_if);
	NOT_REACHED(); // 이 코드는 도달하면 안된다...!
}

/* 스레드 TID가 종료될 때까지 기다린 후 그 종료 상태를 반환합니다.
 * 커널에 의해 종료된 경우(예: 예외로 인해 종료됨), -1을 반환합니다.
 * TID가 유효하지 않거나 호출 프로세스의 자식이 아닌 경우,
 * 또는 이미 주어진 TID에 대해 process_wait()이 성공적으로 호출된 경우,
 * 기다리지 않고 즉시 -1을 반환합니다.
 *
 * 이 함수는 문제 2-2에서 구현될 것입니다. 현재는 아무 것도 하지 않습니다. */
int process_wait(tid_t child_tid UNUSED)
{
	/* XXX: 힌트) Pintos가 process_wait(initd)일 때 종료됩니다.
	 * XXX: process_wait을 구현하기 전에 여기에 무한 루프를 추가하는 것을 추천합니다. */

	// for (int i = 0; i < 1000000000; i++) {
		
	// }

	struct thread *child = get_child_process(child_tid);
	if (child == NULL)
		return -1;

	sema_down(&child->wait_sema);
	list_remove(&child->child_elem);
	sema_up(&child->exit_sema);
	return child->exit_status;
}

/* Exit the process. This function is called by thread_exit (). */
void process_exit(void)
{
	struct thread *cur = thread_current();

	// 1) FDT의 모든 파일을 닫고 메모리를 반환한다.
	// for (int i = 2; i < FDT_COUNT_LIMIT; i++)
	// 	close(i);
	// palloc_free_page(cur->fdt);
	// 프로세스에 열린 모든 파일을 닫는다.
	for (int i = cur->next_fd - 1; i >= 2; i--)
	{
		if (cur->fdt[i] != NULL)
		{
			process_close_file(i);
		}
	}
	process_cleanup();

	// 3) 자식이 종료될 때까지 대기하고 있는 부모에게 signal을 보낸다.
	sema_up(&cur->wait_sema);
	// 4) 부모의 signal을 기다린다. 대기가 풀리고 나서 do_schedule(THREAD_DYING)이 이어져 다른 스레드가 실행된다.
	sema_down(&cur->exit_sema);
}

/* 현재 프로세스의 자원을 해제합니다. */
static void
process_cleanup(void)
{
	struct thread *curr = thread_current();

#ifdef VM
	supplemental_page_table_kill(&curr->spt);
#endif

	uint64_t *pml4;
	/* 현재 프로세스의 페이지 디렉토리를 삭제하고 커널 전용 페이지 디렉토리로 전환합니다. */
	pml4 = curr->pml4;
	if (pml4 != NULL)
	{
		/* 여기에서 올바른 순서가 중요합니다. cur->pagedir을 NULL로 설정한 후에
		 * 페이지 디렉토리를 전환해야 타이머 인터럽트가 프로세스 페이지 디렉토리로 전환하지 않습니다.
		 * 기본 페이지 디렉토리를 활성화한 후에 프로세스의 페이지 디렉토리를 삭제해야 하며,
		 * 그렇지 않으면 활성 페이지 디렉토리가 해제(또는 정리)된 페이지 디렉토리가 됩니다. */
		curr->pml4 = NULL;
		pml4_activate(NULL);
		pml4_destroy(pml4);
	}
}

/* 다음 스레드에서 사용자 코드를 실행하기 위해 CPU를 설정합니다.
 * 이 함수는 매 컨텍스트 전환 시 호출됩니다. */
void process_activate(struct thread *next)
{
	/* 스레드의 페이지 테이블을 활성화합니다. */
	pml4_activate(next->pml4);

	/* 인터럽트 처리를 위해 스레드의 커널 스택을 설정합니다. */
	tss_update(next);
}

/* 우리는 ELF 바이너리를 로드합니다. 다음 정의는 ELF 사양([ELF1])에서 가져온 것입니다. */

/* ELF 타입. [ELF1] 1-2 참조. */
#define EI_NIDENT 16

#define PT_NULL 0			/* 무시. */
#define PT_LOAD 1			/* 로드 가능한 세그먼트. */
#define PT_DYNAMIC 2		/* 동적 링크 정보. */
#define PT_INTERP 3			/* 동적 로더의 이름. */
#define PT_NOTE 4			/* 보조 정보. */
#define PT_SHLIB 5			/* 예약됨. */
#define PT_PHDR 6			/* 프로그램 헤더 테이블. */
#define PT_STACK 0x6474e551 /* 스택 세그먼트. */

#define PF_X 1 /* 실행 가능. */
#define PF_W 2 /* 쓰기 가능. */
#define PF_R 4 /* 읽기 가능. */

/* 실행 가능한 헤더. [ELF1] 1-4부터 1-8 참조.
 * 이는 ELF 바이너리의 맨 앞에 나타납니다. */
struct ELF64_hdr
{
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
/* ELF 프로그램 헤더 구조체 */
struct ELF64_PHDR
{
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

static bool setup_stack(struct intr_frame *if_);
static bool validate_segment(const struct Phdr *, struct file *);
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
						 uint32_t read_bytes, uint32_t zero_bytes,
						 bool writable);

/* FILE_NAME에서 ELF 실행 파일을 현재 스레드로 로드합니다.
 * 실행 파일의 진입 지점을 *RIP에 저장하고
 * 초기 스택 포인터를 *RSP에 저장합니다.
 * 성공 시 true를 반환하고, 실패 시 false를 반환합니다. */
static bool
load(const char *file_name, struct intr_frame *if_)
{
	struct thread *t = thread_current();
	// 리눅스와 같은 운영 체제에서 실행 파일, 오브젝트 파일, 공유 라이브러리 등을 저장하는 파일 포맷
	// 파일을 올바르게 로드하고 실행하기 위해 필요한 메타데이터
	struct ELF ehdr;		  // ELF 헤더 정보
	struct file *file = NULL; // 파일 시스템에서 열려 있는 파일을 가리키는 포인터
	off_t file_ofs;			  // 파일의 오프셋을 저장하는 변수로, 파일에서 프로그램 헤더를 읽을 때 사용
	bool success = false;	  // 로드 성공 여부
	int i;

	char *argv[30], *token, *save_ptr;
	int argc = 0;
	for (token = strtok_r(file_name, " ", &save_ptr); token != NULL; token = strtok_r(NULL, " ", &save_ptr))
	{
		argv[argc] = token;
		argc++;
	}

	/* 페이지 디렉토리를 할당하고 활성화합니다. */
	// 각 프로세스가 사용하는 가상 메모리 주소와
	// 실제 물리 메모리 주소 사이의 매핑 정보를 담고 있는 중요한 데이터 구조
	// PML4는 이 페이지 테이블의 최상위 단계로,
	// 프로세스가 사용하는 모든 가상 주소 공간에 대한 전체 매핑을 관리
	t->pml4 = pml4_create(); // 페이지 테이블을 만든다.
	if (t->pml4 == NULL)
		goto done;
	process_activate(thread_current()); // 페이지 테이블을 활성화한다. 현재 스레드를 위한 메모리 매핑을 설정했다.

	/* 실행 파일 열기 */
	file = filesys_open(argv[0]); // 파일 시스템에서 실행 파일을 엽니다.
	if (file == NULL)			  // 파일 열기에 실패한 경우
	{
		printf("load: %s: open failed\n", file_name); // 실패 메시지를 출력하고
		goto done;									  // 실패 처리로 이동합니다.
	}

	/* 실행 파일 헤더를 읽고 검증합니다. */
	if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||			  // ELF 헤더 크기만큼 파일을 읽고
		memcmp(ehdr.e_ident, "\177ELF\2\1\1", 7) ||						  // ELF 헤더의 식별 정보가 유효한지 확인합니다.
		ehdr.e_type != 2 || ehdr.e_machine != 0x3E ||					  // 파일 타입이 실행 파일인지, 아키텍처가 x86-64인지 확인합니다.
		ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Phdr) || // ELF 버전과 프로그램 헤더 크기를 확인합니다.
		ehdr.e_phnum > 1024)											  // 프로그램 헤더의 개수가 허용된 최대 개수보다 큰지 확인합니다.
	{
		printf("load: %s: error loading executable\n", file_name); // 유효하지 않은 경우 오류 메시지를 출력하고
		goto done;												   // 실패 처리로 이동합니다.
	}

	/* Read program headers. */
	// 프로그램 헤더를 읽고 각각의 세그먼트를 처리한다.
	file_ofs = ehdr.e_phoff;		   // 프로그램 헤더 테이블의 시작 위치를 가져옵니다.
	for (i = 0; i < ehdr.e_phnum; i++) // 프로그램 헤더 수만큼 반복합니다.
	{
		struct Phdr phdr; // 프로그램 헤더 구조체를 선언합니다.

		if (file_ofs < 0 || file_ofs > file_length(file)) // 파일 오프셋이 유효한지 확인합니다.
			goto done;									  // 유효하지 않으면 실패 처리로 이동합니다.
		file_seek(file, file_ofs);						  // 파일 오프셋으로 파일을 탐색합니다.

		if (file_read(file, &phdr, sizeof phdr) != sizeof phdr) // 프로그램 헤더를 읽습니다.
			goto done;											// 읽기에 실패하면 실패 처리로 이동합니다.
		file_ofs += sizeof phdr;								// 다음 프로그램 헤더로 이동합니다.

		switch (phdr.p_type) // 프로그램 헤더 타입에 따라 처리합니다.
		{
			// 이미 다른 방식으로 다루고 있기 때문에 무시
		case PT_NULL:  // 의미없이 예약된 실제 사용되지 않는 데이터
		case PT_NOTE:  // 주로 메타데이터를 포함하고 있음
		case PT_PHDR:  // 세그먼트 프로그램 헤더 자체를 가리킴 / 로더는 프로그램을 메모리에 올리기 위한 목적이고 프로그램 실행 자체에서 필요한 특정 정보들은 load 하지 않음
		case PT_STACK: // 스택과 관련된 정보 pintos 자체적으로 사용자 스택을 설정하고 관리하기 때문에 로드하지 않음
		default:
			/* 이 세그먼트 무시 */
			break; // 무시할 세그먼트는 아무 작업도 하지 않습니다.
		// pintos에서 아예 지원하지 않기 때문에 실패
		case PT_DYNAMIC:					   // 동적 링크 정보를 담고 있음 -> pintos 동적 링크 기능을 지원하지 않음
		case PT_INTERP:						   // 인터프리터 경로 -> 특정 해석기가 필요한 경우 사용 pintos 지원안함
		case PT_SHLIB:						   // 예약된 타입 보통 프로그램에서 사용하지 않음
			goto done;						   // 로드할 수 없는 세그먼트 유형은 실패 처리로 이동합니다.
		case PT_LOAD:						   // 로드할 수 있는 세그먼트인 경우
			if (validate_segment(&phdr, file)) // 세그먼트가 유효한지 확인합니다.
			{
				bool writable = (phdr.p_flags & PF_W) != 0;	  // 세그먼트가 쓰기 가능한지 여부를 확인합니다.
				uint64_t file_page = phdr.p_offset & ~PGMASK; // 파일의 시작 페이지를 계산합니다.
				uint64_t mem_page = phdr.p_vaddr & ~PGMASK;	  // 메모리의 시작 페이지를 계산합니다.
				uint64_t page_offset = phdr.p_vaddr & PGMASK; // 페이지 오프셋을 계산합니다.
				uint32_t read_bytes, zero_bytes;

				if (phdr.p_filesz > 0) // 파일 크기가 0보다 큰 경우
				{
					/* 일반 세그먼트.
					 * 디스크에서 초기 부분을 읽고 나머지는 0으로 설정합니다. */
					read_bytes = page_offset + phdr.p_filesz;								  // 읽을 바이트 수를 계산합니다.
					zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes); // 나머지 부분을 0으로 채웁니다.
				}
				else
				{
					/* 완전히 0으로 설정.
					 * 디스크에서 아무 것도 읽지 않습니다. */
					read_bytes = 0;											   // 읽을 바이트가 없고
					zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE); // 전체를 0으로 채웁니다.
				}

				if (!load_segment(file, file_page, (void *)mem_page, read_bytes, zero_bytes, writable))
					goto done; // 세그먼트 로드에 실패하면 실패 처리로 이동합니다.
			}
			else
				goto done; // 세그먼트가 유효하지 않으면 실패 처리로 이동합니다.
			break;
		}
	}

	/* Set up stack. */
	if (!setup_stack(if_)) // 스택 설정
		goto done;

	/* Start address. */
	if_->rip = ehdr.e_entry; // 시작주소 설정

	// 인자들을 스택에 저장하고, 각 인자의 주소를 저장할 포인터 배열의 위치를 확보
	char *argv_addr[10]; // 스택에서 각 인자의 주소를 저장하기 위한 배열
	for (int i = argc - 1; i >= 0; i--)
	{
		for (int j = strlen(argv[i]); j >= 0; j--)
		{ // NULL 문자까지 복사
			if_->rsp--;
			*(char *)if_->rsp = argv[i][j];
		}
		argv_addr[i] = (char *)if_->rsp; // 스택에 저장된 각 인자의 주소를 저장
	}

	// 8바이트 정렬: 스택 포인터를 8바이트 단위로 정렬
	while (if_->rsp % 8 != 0)
	{
		if_->rsp--;
		*(uint8_t *)if_->rsp = 0;
	}

	// NULL 포인터 저장 (argv[argc] == NULL)
	if_->rsp -= sizeof(char *);
	*(char **)if_->rsp = NULL;

	// 각 인자의 주소를 역순으로 스택에 저장
	for (int i = argc - 1; i >= 0; i--)
	{
		if_->rsp -= sizeof(char *);
		*(char **)if_->rsp = argv_addr[i]; // 스택에 저장된 인자의 주소를 저장
	}

	// Return address를 0으로 설정
	if_->rsp -= sizeof(void *);
	*(void **)if_->rsp = 0; // return address를 0으로 설정

	if_->R.rdi = argc;
	if_->R.rsi = if_->rsp+8;

	success = true;

done:
	/* We arrive here whether the load is successful or not. */
	file_close(file);
	return success;
}

/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment(const struct Phdr *phdr, struct file *file)
{
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t)file_length(file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr((void *)phdr->p_vaddr))
		return false;
	if (!is_user_vaddr((void *)(phdr->p_vaddr + phdr->p_memsz)))
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

int process_add_file(struct file *f)
{
	struct thread *cur_t = thread_current();
	int ret_fd = cur_t->next_fd;
	if (ret_fd == MAX_FD)
	{
		return -1;
	}

	cur_t->fdt[ret_fd] = f;
	cur_t->next_fd += 1;

	return ret_fd;
}

void process_close_file(int fd)
{
	struct thread *cur_t = thread_current();
	struct file *cur_file = process_get_file(fd);

	if (cur_file == NULL)
	{
		return;
	}
	file_close(fd);

	cur_t->fdt[fd] = NULL;
}

#ifndef VM
/* 이 블록의 코드는 프로젝트 2에서만 사용됩니다.
 * 프로젝트 2 전반에 걸쳐 함수를 구현하려면 #ifndef 매크로 외부에서 구현하십시오. */

/* load() helpers. */
static bool install_page(void *upage, void *kpage, bool writable);
/* FILE에서 OFS 오프셋에서 시작하는 세그먼트를 주소 UPAGE에 로드합니다.
 * 총 READ_BYTES + ZERO_BYTES 바이트의 가상 메모리가 초기화됩니다:
 *
 * - READ_BYTES 바이트는 FILE에서 OFS에서 시작하여 UPAGE에 읽어야 합니다.
 *
 * - READ_BYTES 뒤에 있는 UPAGE + ZERO_BYTES 바이트는 0으로 채워야 합니다.
 *
 * 이 함수로 초기화된 페이지는 WRITABLE이 true일 경우 사용자 프로세스가 수정할 수 있고,
 * 그렇지 않은 경우 읽기 전용입니다.
 *
 * 성공 시 true를 반환하고, 메모리 할당 오류나 디스크 읽기 오류가 발생하면 false를 반환합니다. */
static bool
load_segment(struct file *file, off_t ofs, uint8_t *upage,
			 uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
	ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT(pg_ofs(upage) == 0);
	ASSERT(ofs % PGSIZE == 0);

	file_seek(file, ofs);
	while (read_bytes > 0 || zero_bytes > 0)
	{
		/* 이 페이지를 채우는 방법을 계산합니다.
		 * FILE에서 PAGE_READ_BYTES 바이트를 읽고
		 * 마지막 PAGE_ZERO_BYTES 바이트를 0으로 채웁니다. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* 메모리 페이지를 가져옵니다. */
		uint8_t *kpage = palloc_get_page(PAL_USER);
		if (kpage == NULL)
			return false;

		/* 이 페이지를 로드합니다. */
		if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes)
		{
			palloc_free_page(kpage);
			return false;
		}
		memset(kpage + page_read_bytes, 0, page_zero_bytes);

		/* 프로세스의 주소 공간에 페이지를 추가합니다. */
		if (!install_page(upage, kpage, writable))
		{
			printf("fail\n");
			palloc_free_page(kpage);
			return false;
		}

		/* 다음으로 진행합니다. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* USER_STACK에 0으로 채워진 페이지를 매핑하여 최소한의 스택을 만듭니다. */
static bool
setup_stack(struct intr_frame *if_)
{
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page(PAL_USER | PAL_ZERO);
	if (kpage != NULL)
	{
		success = install_page(((uint8_t *)USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page(kpage);
	}
	return success;
}

/* 사용자 가상 주소 UPAGE에서 커널 가상 주소 KPAGE로의 매핑을 페이지 테이블에 추가합니다.
 * WRITABLE이 true일 경우, 사용자 프로세스가 페이지를 수정할 수 있고,
 * 그렇지 않으면 읽기 전용입니다.
 * UPAGE는 이미 매핑되어 있으면 안 됩니다.
 * KPAGE는 palloc_get_page()로 사용자 풀에서 얻은 페이지여야 합니다.
 * 성공 시 true를 반환하고, UPAGE가 이미 매핑되어 있거나 메모리 할당이 실패한 경우 false를 반환합니다. */
static bool
install_page(void *upage, void *kpage, bool writable)
{
	struct thread *t = thread_current();

	/* 해당 가상 주소에 이미 페이지가 없는지 확인한 후, 페이지를 매핑합니다. */
	return (pml4_get_page(t->pml4, upage) == NULL && pml4_set_page(t->pml4, upage, kpage, writable));
}

#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool
lazy_load_segment(struct page *page, void *aux)
{
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
load_segment(struct file *file, off_t ofs, uint8_t *upage,
			 uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
	ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT(pg_ofs(upage) == 0);
	ASSERT(ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0)
	{
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		void *aux = NULL;
		if (!vm_alloc_page_with_initializer(VM_ANON, upage,
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
setup_stack(struct intr_frame *if_)
{
	bool success = false;
	void *stack_bottom = (void *)(((uint8_t *)USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */

	return success;
}
#endif /* VM */
