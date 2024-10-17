#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

struct aux {
    struct file *file;
    off_t offset;
    size_t page_read_bytes;
};

tid_t process_create_initd( const char *file_name );
tid_t process_fork( const char *name, struct intr_frame *if_ );
int process_exec( void *f_name );
int process_wait( tid_t );
void process_exit( void );
void process_activate( struct thread *next );
void argument_stack( char **parse, int count, void **rsp );
struct thread *get_child_process( int pid );

int process_add_file( struct file *f );
struct file *process_get_file( int fd );
void process_close_file( int fd );
bool lazy_load_segment( struct page *page, void *aux );
#endif /* userprog/process.h */
