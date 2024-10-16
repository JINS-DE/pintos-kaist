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
#include "userprog/syscall.h"
#include "vm/vm.h"

static void process_cleanup( void );
static bool load( const char *file_name, struct intr_frame *if_ );
static void initd( void *f_name );
static void __do_fork( void * );
struct thread *get_child_process( int pid );

/* initd와 다른 프로세스를 위한 일반적인 프로세스 초기화 함수 */
static void process_init( void ) { struct thread *current = thread_current(); }

/* "initd"라는 첫 번째 사용자 프로그램을 FILE_NAME에서 로드하여 시작합니다.
 * 새 스레드는 process_create_initd()가 반환되기 전에 스케줄링될 수 있으며,
 * 심지어 종료될 수도 있습니다. initd의 스레드 ID를 반환하거나, 스레드를
 * 생성할 수 없으면 TID_ERROR를 반환합니다.
 * 주의: 이 함수는 한 번만 호출되어야 합니다. */
tid_t process_create_initd( const char *file_name ) {
    char *fn_copy;
    tid_t tid;

    /* Make a copy of FILE_NAME.
     * Otherwise there's a race between the caller and load(). */
    fn_copy = palloc_get_page( 0 );
    if ( fn_copy == NULL ) return TID_ERROR;
    strlcpy( fn_copy, file_name, PGSIZE );

    // Argument Passing ~
    char *save_ptr;
    strtok_r( file_name, " ", &save_ptr );
    // ~ Argument Passing

    /* Create a new thread to execute FILE_NAME. */
    tid = thread_create( file_name, PRI_DEFAULT, initd, fn_copy );
    if ( tid == TID_ERROR ) palloc_free_page( fn_copy );
    return tid;
}
/* 첫 번째 사용자 프로세스를 시작하는 스레드 함수 */
static void initd( void *f_name ) {
#ifdef VM
    supplemental_page_table_init( &thread_current()->spt );
#endif

    process_init();

    if ( process_exec( f_name ) < 0 ) PANIC( "Fail to launch initd\n" );
    NOT_REACHED();
}
/* 현재 프로세스를 `name`으로 복제합니다. 새 프로세스의 스레드 ID를 반환하거나,
 * 스레드를 생성할 수 없으면 TID_ERROR를 반환합니다. */
tid_t process_fork( const char *name, struct intr_frame *if_ UNUSED ) {
    /* Clone current thread to new thread.*/
    // 현재 스레드의 parent_if에 복제해야 하는 if를 복사한다.
    struct thread *cur = thread_current();
    memcpy( &cur->parent_if, if_, sizeof( struct intr_frame ) );

    // 현재 스레드를 fork한 new 스레드를 생성한다.
    tid_t pid = thread_create( name, PRI_DEFAULT, __do_fork, cur );
    if ( pid == TID_ERROR ) return TID_ERROR;

    // 자식이 로드될 때까지 대기하기 위해서 방금 생성한 자식 스레드를 찾는다.
    struct thread *child = get_child_process( pid );

    // 현재 스레드는 생성만 완료된 상태이다. 생성되어서 ready_list에 들어가고 실행될 때 __do_fork 함수가 실행된다.
    // __do_fork 함수가 실행되어 로드가 완료될 때까지 부모는 대기한다.
    sema_down( &child->load_sema );

    // 자식 프로세스의 pid를 반환한다.
    return pid;
}
// tid는 단순히 스레드의 ID일 뿐이고,
// 실제로 해당 스레드의 데이터(예: 세마포어,
// 스택 프레임 등)에 접근하려면 그 스레드의 구조체 포인터가 필요합니다.
// 그래서 get_child_process()를 통해 자식 스레드의 구조체를 찾는 과정
struct thread *get_child_process( int pid ) {
    struct thread *cur = thread_current();
    struct list *child_list = &cur->child_list;
    for ( struct list_elem *e = list_begin( child_list ); e != list_end( child_list ); e = list_next( e ) ) {
        struct thread *t = list_entry( e, struct thread, child_elem );
        if ( t->tid == pid ) {
            return t;
        }
    }
    return NULL;
}

#ifndef VM
/* 부모의 주소 공간을 pml4_for_each 함수에 전달하여 복제합니다.
 * 이는 프로젝트 2에만 해당됩니다. */
static bool duplicate_pte( uint64_t *pte, void *va, void *aux ) {
    struct thread *current = thread_current();
    struct thread *parent = (struct thread *)aux;
    void *parent_page;
    void *newpage;
    bool writable;

    /* 1. TODO: If the parent_page is kernel page, then return immediately. */
    if ( is_kernel_vaddr( va ) ) return true;

    /* 2. Resolve VA from the parent's page map level 4. */
    parent_page = pml4_get_page( parent->pml4, va );
    if ( parent_page == NULL ) return false;

    /* 3. TODO: Allocate new PAL_USER page for the child and set result to
     *    TODO: NEWPAGE. */
    newpage = palloc_get_page( PAL_USER | PAL_ZERO );
    if ( newpage == NULL ) return false;

    /* 4. TODO: Duplicate parent's page to the new page and
     *    TODO: check whether parent's page is writable or not (set WRITABLE
     *    TODO: according to the result). */
    memcpy( newpage, parent_page, PGSIZE );
    writable = is_writable( pte );

    /* 5. Add new page to child's page table at address VA with WRITABLE
     *    permission. */
    if ( !pml4_set_page( current->pml4, va, newpage, writable ) ) {
        /* 6. TODO: if fail to insert page, do error handling. */
        return false;
    }
    return true;
}
#endif
/* 부모의 실행 컨텍스트를 복사하는 스레드 함수
 * 힌트) parent->tf는 프로세스의 사용자 영역 컨텍스트를 포함하지 않습니다.
 *       즉, process_fork의 두 번째 인자를 이 함수에 전달해야 합니다. */
static void __do_fork( void *aux ) {
    struct intr_frame if_;
    struct thread *parent = (struct thread *)aux;
    struct thread *current = thread_current();
    /* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
    struct intr_frame *parent_if = &parent->parent_if;
    bool succ = true;

    /* 1. Read the cpu context to local stack. */
    memcpy( &if_, parent_if, sizeof( struct intr_frame ) );
    if_.R.rax = 0;  // 자식 프로세스의 리턴값은 0

    /* 2. Duplicate PT */
    current->pml4 = pml4_create();
    if ( current->pml4 == NULL ) goto error;

    process_activate( current );
#ifdef VM
    supplemental_page_table_init( &current->spt );
    if ( !supplemental_page_table_copy( &current->spt, &parent->spt ) ) goto error;
#else
    if ( !pml4_for_each( parent->pml4, duplicate_pte, parent ) ) goto error;
#endif

    /* TODO: Your code goes here.
     * TODO: Hint) To duplicate the file object, use `file_duplicate`
     * TODO:       in include/filesys/file.h. Note that parent should not return
     * TODO:       from the fork() until this function successfully duplicates
     * TODO:       the resources of parent.*/

    // FDT 복사
    for ( int i = 0; i < FDT_COUNT_LIMIT; i++ ) {
        struct file *file = parent->fdt[i];
        if ( file == NULL ) continue;
        if ( file > 2 ) file = file_duplicate( file );
        current->fdt[i] = file;
    }
    current->next_fd = parent->next_fd;

    // 로드가 완료될 때까지 기다리고 있던 부모 대기 해제
    sema_up( &current->load_sema );
    process_init();

    /* Finally, switch to the newly created process. */
    if ( succ ) do_iret( &if_ );
error:
    sema_up( &current->load_sema );
    exit( TID_ERROR );
}
/* f_name으로 현재 실행 컨텍스트를 전환합니다.
 * 실패 시 -1을 반환합니다. */
int process_exec( void *f_name ) {  // 인자: 실행하려는 이진 파일의 이름
    char *file_name = f_name;
    bool success;

    /* We cannot use the intr_frame in the thread structure.
     * This is because when current thread rescheduled,
     * it stores the execution information to the member. */
    struct intr_frame _if;
    _if.ds = _if.es = _if.ss = SEL_UDSEG;
    _if.cs = SEL_UCSEG;
    _if.eflags = FLAG_IF | FLAG_MBS;

    /* We first kill the current context */
    process_cleanup();

    // Argument Passing ~
    char *parse[64];
    char *token, *save_ptr;
    int count = 0;
    for ( token = strtok_r( file_name, " ", &save_ptr ); token != NULL; token = strtok_r( NULL, " ", &save_ptr ) ) parse[count++] = token;
    // ~ Argument Passing

    /* And then load the binary */
    lock_acquire( &filesys_lock );
    success = load( file_name, &_if );
    lock_release( &filesys_lock );
    // 이진 파일을 디스크에서 메모리로 로드한다.
    // 로드된 후 실행할 메인 함수의 시작 주소 필드 초기화 (if_.rip)
    // user stack의 top 포인터 초기화 (if_.rsp)
    // 위 과정을 성공하면 실행을 계속하고, 실패하면 스레드가 종료된다.

    // Argument Passing ~
    argument_stack( parse, count, &_if.rsp );  // 함수 내부에서 parse와 rsp의 값을 직접 변경하기 위해 주소 전달
    _if.R.rdi = count;
    _if.R.rsi = (char *)_if.rsp + 8;

    // hex_dump(_if.rsp, _if.rsp, USER_STACK - (uint64_t)_if.rsp, true); // user stack을 16진수로 프린트
    // ~ Argument Passing

    /* If load failed, quit. */
    palloc_free_page( file_name );
    if ( !success ) return -1;

    /* Start switched process. */
    do_iret( &_if );
    NOT_REACHED();
}

void argument_stack( char **parse, int count, void **rsp )  // 주소를 전달받았으므로 이중 포인터 사용
{
    // 프로그램 이름, 인자 문자열 push
    for ( int i = count - 1; i > -1; i-- ) {
        for ( int j = strlen( parse[i] ); j > -1; j-- ) {
            ( *rsp )--;                    // 스택 주소 감소
            **(char **)rsp = parse[i][j];  // 주소에 문자 저장
        }
        parse[i] = *(char **)rsp;  // parse[i]에 현재 rsp의 값 저장해둠(지금 저장한 인자가 시작하는 주소값)
    }

    // 정렬 패딩 push
    int padding = (int)*rsp % 8;
    for ( int i = 0; i < padding; i++ ) {
        ( *rsp )--;
        **(uint8_t **)rsp = 0;  // rsp 직전까지 값 채움
    }

    // 인자 문자열 종료를 나타내는 0 push
    ( *rsp ) -= 8;
    **(char ***)rsp = 0;  // char* 타입의 0 추가

    // 각 인자 문자열의 주소 push
    for ( int i = count - 1; i > -1; i-- ) {
        ( *rsp ) -= 8;               // 다음 주소로 이동
        **(char ***)rsp = parse[i];  // char* 타입의 주소 추가
    }

    // return address push
    ( *rsp ) -= 8;
    **(void ***)rsp = 0;  // void* 타입의 0 추가
}

/* 스레드 TID가 종료될 때까지 기다린 후 그 종료 상태를 반환합니다.
 * 커널에 의해 종료된 경우(예: 예외로 인해 종료됨), -1을 반환합니다.
 * TID가 유효하지 않거나 호출 프로세스의 자식이 아닌 경우,
 * 또는 이미 주어진 TID에 대해 process_wait()이 성공적으로 호출된 경우,
 * 기다리지 않고 즉시 -1을 반환합니다.
 *
 * 이 함수는 문제 2-2에서 구현될 것입니다. 현재는 아무 것도 하지 않습니다. */
int process_wait( tid_t child_tid UNUSED ) {
    /* XXX: 힌트) Pintos가 process_wait(initd)일 때 종료됩니다.
     * XXX: process_wait을 구현하기 전에 여기에 무한 루프를 추가하는 것을 추천합니다. */
    struct thread *child = get_child_process( child_tid );
    if ( child == NULL ) return -1;

    sema_down( &child->wait_sema );
    list_remove( &child->child_elem );
    sema_up( &child->exit_sema );
    return child->exit_status;
}

/* Exit the process. This function is called by thread_exit (). */
void process_exit( void ) {
    struct thread *cur = thread_current();

    // 1) FDT의 모든 파일을 닫는다.
    for ( int i = 2; i < FDT_COUNT_LIMIT; i++ ) {
        process_close_file( i );
    }
    // FDT의 메모리를 반환한다.
    palloc_free_multiple( cur->fdt, FDT_PAGES );

    // 2) 현재 실행 중인 파일도 닫는다.
    file_close( cur->running );
    process_cleanup();

    // 3) 자식이 종료될 때까지 대기하고 있는 부모에게 signal을 보낸다.
    sema_up( &cur->wait_sema );
    // 4) 부모의 signal을 기다린다. 대기가 풀리고 나서 do_schedule(THREAD_DYING)이 이어져 다른 스레드가 실행된다.
    sema_down( &cur->exit_sema );
}

/* 현재 프로세스의 자원을 해제합니다. */
static void process_cleanup( void ) {
    struct thread *curr = thread_current();

#ifdef VM
    supplemental_page_table_kill( &curr->spt );
#endif

    uint64_t *pml4;
    /* 현재 프로세스의 페이지 디렉토리를 삭제하고 커널 전용 페이지 디렉토리로 전환합니다. */
    pml4 = curr->pml4;
    if ( pml4 != NULL ) {
         /* 여기에서 올바른 순서가 중요합니다. cur->pagedir을 NULL로 설정한 후에
         * 페이지 디렉토리를 전환해야 타이머 인터럽트가 프로세스 페이지 디렉토리로 전환하지 않습니다.
         * 기본 페이지 디렉토리를 활성화한 후에 프로세스의 페이지 디렉토리를 삭제해야 하며,
         * 그렇지 않으면 활성 페이지 디렉토리가 해제(또는 정리)된 페이지 디렉토리가 됩니다. */
        curr->pml4 = NULL;
        pml4_activate( NULL );
        pml4_destroy( pml4 );
    }
}

/* 다음 스레드에서 사용자 코드를 실행하기 위해 CPU를 설정합니다.
 * 이 함수는 매 컨텍스트 전환 시 호출됩니다. */
void process_activate( struct thread *next ) {
    /* 스레드의 페이지 테이블을 활성화합니다. */
    pml4_activate( next->pml4 );

    /* 인터럽트 처리를 위해 스레드의 커널 스택을 설정합니다. */
    tss_update( next );
}

/* 우리는 ELF 바이너리를 로드합니다. 다음 정의는 ELF 사양([ELF1])에서 가져온 것입니다. */

/* ELF 타입. [ELF1] 1-2 참조. */
#define EI_NIDENT 16

#define PT_NULL 0           /* 무시. */
#define PT_LOAD 1           /* 로드 가능한 세그먼트. */
#define PT_DYNAMIC 2        /* 동적 링크 정보. */
#define PT_INTERP 3         /* 동적 로더의 이름. */
#define PT_NOTE 4           /* 보조 정보. */
#define PT_SHLIB 5          /* 예약됨. */
#define PT_PHDR 6           /* 프로그램 헤더 테이블. */
#define PT_STACK 0x6474e551 /* 스택 세그먼트. */

#define PF_X 1 /* 실행 가능. */
#define PF_W 2 /* 쓰기 가능. */
#define PF_R 4 /* 읽기 가능. */

/* 실행 가능한 헤더. [ELF1] 1-4부터 1-8 참조.
 * 이는 ELF 바이너리의 맨 앞에 나타납니다. */
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
/* ELF 프로그램 헤더 구조체 */
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

static bool setup_stack( struct intr_frame *if_ );
static bool validate_segment( const struct Phdr *, struct file * );
static bool load_segment( struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes, bool writable );

/* FILE_NAME에서 ELF 실행 파일을 현재 스레드로 로드합니다.
 * 실행 파일의 진입 지점을 *RIP에 저장하고
 * 초기 스택 포인터를 *RSP에 저장합니다.
 * 성공 시 true를 반환하고, 실패 시 false를 반환합니다. */
static bool load( const char *file_name, struct intr_frame *if_ ) {
    struct thread *t = thread_current();
    struct ELF ehdr;
    struct file *file = NULL;
    off_t file_ofs;
    bool success = false;
    int i;

    /* Allocate and activate page directory. */
    t->pml4 = pml4_create();  // 페이지 dir(페이지 테이블 포인터) 생성
    if ( t->pml4 == NULL ) goto done;
    process_activate( thread_current() );  // 이 함수 안에서 페이지 테이블 활성화함

    /* Open executable file. */
    file = filesys_open( file_name );
    if ( file == NULL ) {
        printf( "load: %s: open failed\n", file_name );
        goto done;
    }

    /* Read and verify executable header. */
    if ( file_read( file, &ehdr, sizeof ehdr ) != sizeof ehdr || memcmp( ehdr.e_ident, "\177ELF\2\1\1", 7 ) || ehdr.e_type != 2 || ehdr.e_machine != 0x3E  // amd64
         || ehdr.e_version != 1 || ehdr.e_phentsize != sizeof( struct Phdr ) || ehdr.e_phnum > 1024 ) {
        printf( "load: %s: error loading executable\n", file_name );
        goto done;
    }

    /* Read program headers. */
    file_ofs = ehdr.e_phoff;
    for ( i = 0; i < ehdr.e_phnum; i++ ) {
        struct Phdr phdr;

        if ( file_ofs < 0 || file_ofs > file_length( file ) ) goto done;
        file_seek( file, file_ofs );

        if ( file_read( file, &phdr, sizeof phdr ) != sizeof phdr ) goto done;
        file_ofs += sizeof phdr;
        switch ( phdr.p_type ) {
            case PT_NULL:
            case PT_NOTE:
            case PT_PHDR:
            case PT_STACK:
            default:
                /* Ignore this segment. */
                break;
            case PT_DYNAMIC:
            case PT_INTERP:
            case PT_SHLIB:
                goto done;
            case PT_LOAD:
                if ( validate_segment( &phdr, file ) ) {
                    bool writable = ( phdr.p_flags & PF_W ) != 0;
                    uint64_t file_page = phdr.p_offset & ~PGMASK;
                    uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
                    uint64_t page_offset = phdr.p_vaddr & PGMASK;
                    uint32_t read_bytes, zero_bytes;
                    if ( phdr.p_filesz > 0 ) {
                        /* Normal segment.
                         * Read initial part from disk and zero the rest. */
                        read_bytes = page_offset + phdr.p_filesz;
                        zero_bytes = ( ROUND_UP( page_offset + phdr.p_memsz, PGSIZE ) - read_bytes );
                    } else {
                        /* Entirely zero.
                         * Don't read anything from disk. */
                        read_bytes = 0;
                        zero_bytes = ROUND_UP( page_offset + phdr.p_memsz, PGSIZE );
                    }
                    if ( !load_segment( file, file_page, (void *)mem_page, read_bytes, zero_bytes, writable ) ) goto done;
                } else
                    goto done;
                break;
        }
    }

    // 스레드가 삭제될 때 파일을 닫을 수 있게 구조체에 파일을 저장해둔다.
    t->running = file;
    // 현재 실행중인 파일은 수정할 수 없게 막는다.
    file_deny_write( file );
    /* Set up stack. */
    if ( !setup_stack( if_ ) )  // user stack 초기화
        goto done;

    /* Start address. */
    if_->rip = ehdr.e_entry;  // entry point 초기화
    // rip: 프로그램 카운터(실행할 다음 인스트럭션의 메모리  주소)

    /* TODO: Your code goes here.
     * TODO: Implement argument passing (see project2/argument_passing.html). */

    success = true;

done:
    /* We arrive here whether the load is successful or not. */
    // 파일을 여기서 닫지 않고 스레드가 삭제될 때 process_exit에서 닫는다.
    // file_close(file);
    return success;
}

/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool validate_segment( const struct Phdr *phdr, struct file *file ) {
    /* p_offset and p_vaddr must have the same page offset. */
    if ( ( phdr->p_offset & PGMASK ) != ( phdr->p_vaddr & PGMASK ) ) return false;

    /* p_offset must point within FILE. */
    if ( phdr->p_offset > (uint64_t)file_length( file ) ) return false;

    /* p_memsz must be at least as big as p_filesz. */
    if ( phdr->p_memsz < phdr->p_filesz ) return false;

    /* The segment must not be empty. */
    if ( phdr->p_memsz == 0 ) return false;

    /* The virtual memory region must both start and end within the
       user address space range. */
    if ( !is_user_vaddr( (void *)phdr->p_vaddr ) ) return false;
    if ( !is_user_vaddr( (void *)( phdr->p_vaddr + phdr->p_memsz ) ) ) return false;

    /* The region cannot "wrap around" across the kernel virtual
       address space. */
    if ( phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr ) return false;

    /* Disallow mapping page 0.
       Not only is it a bad idea to map page 0, but if we allowed
       it then user code that passed a null pointer to system calls
       could quite likely panic the kernel by way of null pointer
       assertions in memcpy(), etc. */
    if ( phdr->p_vaddr < PGSIZE ) return false;

    /* It's okay. */
    return true;
}

int process_add_file( struct file *f ) {
    struct thread *curr = thread_current();
    struct file **fdt = curr->fdt;

    // FDT_COUNT_LIMIT를 넘지 않는 범위 안에서 빈 자리룰 탐색한다.
    while ( curr->next_fd < FDT_COUNT_LIMIT && fdt[curr->next_fd] ) curr->next_fd++;

    // curr->next_fd가 FDT_COUNT_LIMIT보다 크거나 같다 : 빈 자리가 없다.
    if ( curr->next_fd >= FDT_COUNT_LIMIT ) return -1;

    // 빈 자리가 있다면 그곳에 파일 f를 저장한다.
    fdt[curr->next_fd] = f;

    // 저장된 파일의 fd를 반환한다.
    return curr->next_fd;
}

struct file *process_get_file( int fd ) {
    struct thread *curr = thread_current();
    struct file **fdt = curr->fdt;

    // 파일 디스크럽터가 2보다 작다 : 표준 입출력 -> 가져올 수 없다.
    // 파일 디스크럽터가 FDT_COUNT_LIMIT보다 크거나 같다 : 잘못된 fd
    if ( fd < 2 || fd >= FDT_COUNT_LIMIT ) return NULL;

    // 파일 디스크럽터에 해당하는 파일 객체를 반환한다.
    return fdt[fd];
}

void process_close_file( int fd ) {
    struct thread *curr = thread_current();
    struct file **fdt = curr->fdt;

    // 파일 디스크럽터가 2보다 작다 : 표준 입출력 -> 가져올 수 없다.
    // 파일 디스크럽터가 FDT_COUNT_LIMIT보다 크거나 같다 : 잘못된 fd
    if ( fd < 2 || fd >= FDT_COUNT_LIMIT ) return;

    // fdt 안에 해당 파일이 존재하면,
    if ( fdt[fd] != NULL ) {
        file_close( fdt[fd] );  // 해당 파일을 닫는다.
        fdt[fd] = NULL;         // 파일 디스크럽터에서 해당 파일을 지운다.
    }
}

/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

bool lazy_load_segment( struct page *page, void *aux ) {
    struct aux *aux_p = aux;
    struct file *file = aux_p->file;
    off_t offset = aux_p->offset;
    size_t page_read_bytes = aux_p->page_read_bytes;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* TODO: Load the segment from the file */
    /* TODO: This called when the first page fault occurs on address VA. */
    /* TODO: VA is available when calling this function. */
    file_seek( file, offset );                                                               // 파일을 offset부터 읽기
    if ( file_read( file, page->frame->kva, page_read_bytes ) != (off_t)page_read_bytes ) {  // 물리 메모리에서 정상적으로 읽어오는지 확인하고
        palloc_free_page( page->frame->kva );                                                // 제대로 못 읽었다면 free시키고 false 리턴
        return false;
    }

    memset( page->frame->kva + page_read_bytes, 0, page_zero_bytes );  // 남은 page의 데이터들은 0으로 초기화

    return true;
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
static bool load_segment( struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes, bool writable ) {
    ASSERT( ( read_bytes + zero_bytes ) % PGSIZE == 0 );
    ASSERT( pg_ofs( upage ) == 0 );
    ASSERT( ofs % PGSIZE == 0 );

    while ( read_bytes > 0 || zero_bytes > 0 ) {
        /* Do calculate how to fill this page.
         * We will read PAGE_READ_BYTES bytes from FILE
         * and zero the final PAGE_ZERO_BYTES bytes. */
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        struct aux *aux = (struct aux *)malloc( sizeof( struct aux ) );
        aux->file = file;
        aux->offset = ofs;
        aux->page_read_bytes = page_read_bytes;

        if ( !vm_alloc_page_with_initializer( VM_ANON, upage, writable, lazy_load_segment, aux ) )
            return false;

        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        upage += PGSIZE;
        ofs += page_read_bytes;
    }
    return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool setup_stack( struct intr_frame *if_ ) {
    bool success = false;
    void *stack_bottom = (void *)( ( (uint8_t *)USER_STACK ) - PGSIZE );

    if ( vm_alloc_page( VM_ANON | VM_MARKER_0, stack_bottom, 1 ) ) {
        success = vm_claim_page( stack_bottom );

        if ( success ) {
            if_->rsp = USER_STACK;
            thread_current()->stack_alloced_ptr = stack_bottom;
        }
    }

    return success;
}
