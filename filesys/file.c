#include "filesys/file.h"
#include <debug.h>
#include "filesys/inode.h"
#include "threads/malloc.h"

/* 열린 파일을 나타내는 구조체. */
struct file {
    struct inode *inode;        /* 파일의 inode를 가리키는 포인터. 
                                   inode는 파일 시스템에서 파일이나 디렉터리의 메타데이터(크기, 위치, 권한 등)를 
                                   저장하는 데이터 구조입니다. 즉, 이 필드는 파일의 inode 정보를 참조합니다. */
    
    off_t pos;                  /* 파일에서 현재 읽기/쓰기 작업을 할 때의 위치를 나타냅니다.
                                   pos는 오프셋(offset)으로, 파일의 시작 부분으로부터 몇 바이트 떨어진 지점을 나타냅니다. 
                                   예를 들어, 파일의 100번째 바이트에서 작업을 하고 싶다면 이 값은 100이 됩니다. */
    
    bool deny_write;            /* 파일에 대해 쓰기 작업이 금지되었는지 여부를 나타냅니다.
                                   true일 경우, 파일에 쓰기가 불가능하며 이는 file_deny_write() 함수가 호출되었음을 의미합니다. 
                                   이 플래그는 파일이 쓰기 금지 상태인지 아닌지를 추적하는 데 사용됩니다. */
};


/* Opens a file for the given INODE, of which it takes ownership,
 * and returns the new file.  Returns a null pointer if an
 * allocation fails or if INODE is null. */
struct file *
file_open (struct inode *inode) {
	struct file *file = calloc (1, sizeof *file);
	if (inode != NULL && file != NULL) {
		file->inode = inode;
		file->pos = 0;
		file->deny_write = false;
		return file;
	} else {
		inode_close (inode);
		free (file);
		return NULL;
	}
}

/* Opens and returns a new file for the same inode as FILE.
 * Returns a null pointer if unsuccessful. */
struct file *
file_reopen (struct file *file) {
	return file_open (inode_reopen (file->inode));
}

/* Duplicate the file object including attributes and returns a new file for the
 * same inode as FILE. Returns a null pointer if unsuccessful. */
struct file *
file_duplicate (struct file *file) {
	struct file *nfile = file_open (inode_reopen (file->inode));
	if (nfile) {
		nfile->pos = file->pos;
		if (file->deny_write)
			file_deny_write (nfile);
	}
	return nfile;
}

/* Closes FILE. */
void
file_close (struct file *file) {
	if (file != NULL) {
		file_allow_write (file);
		inode_close (file->inode);
		free (file);
	}
}

/* Returns the inode encapsulated by FILE. */
struct inode *
file_get_inode (struct file *file) {
	return file->inode;
}

/* Reads SIZE bytes from FILE into BUFFER,
 * starting at the file's current position.
 * Returns the number of bytes actually read,
 * which may be less than SIZE if end of file is reached.
 * Advances FILE's position by the number of bytes read. */
off_t
file_read (struct file *file, void *buffer, off_t size) {
	off_t bytes_read = inode_read_at (file->inode, buffer, size, file->pos);
	file->pos += bytes_read;
	return bytes_read;
}

/* Reads SIZE bytes from FILE into BUFFER,
 * starting at offset FILE_OFS in the file.
 * Returns the number of bytes actually read,
 * which may be less than SIZE if end of file is reached.
 * The file's current position is unaffected. */
off_t
file_read_at (struct file *file, void *buffer, off_t size, off_t file_ofs) {
	return inode_read_at (file->inode, buffer, size, file_ofs);
}

/* Writes SIZE bytes from BUFFER into FILE,
 * starting at the file's current position.
 * Returns the number of bytes actually written,
 * which may be less than SIZE if end of file is reached.
 * (Normally we'd grow the file in that case, but file growth is
 * not yet implemented.)
 * Advances FILE's position by the number of bytes read. */
off_t
file_write (struct file *file, const void *buffer, off_t size) {
	off_t bytes_written = inode_write_at (file->inode, buffer, size, file->pos);
	file->pos += bytes_written;
	return bytes_written;
}

/* Writes SIZE bytes from BUFFER into FILE,
 * starting at offset FILE_OFS in the file.
 * Returns the number of bytes actually written,
 * which may be less than SIZE if end of file is reached.
 * (Normally we'd grow the file in that case, but file growth is
 * not yet implemented.)
 * The file's current position is unaffected. */
off_t
file_write_at (struct file *file, const void *buffer, off_t size,
		off_t file_ofs) {
	return inode_write_at (file->inode, buffer, size, file_ofs);
}

/* Prevents write operations on FILE's underlying inode
 * until file_allow_write() is called or FILE is closed. */
void
file_deny_write (struct file *file) {
	ASSERT (file != NULL);
	if (!file->deny_write) {
		file->deny_write = true;
		inode_deny_write (file->inode);
	}
}

/* Re-enables write operations on FILE's underlying inode.
 * (Writes might still be denied by some other file that has the
 * same inode open.) */
void
file_allow_write (struct file *file) {
	ASSERT (file != NULL);
	if (file->deny_write) {
		file->deny_write = false;
		inode_allow_write (file->inode);
	}
}

/* Returns the size of FILE in bytes. */
off_t
file_length (struct file *file) {
	ASSERT (file != NULL);
	return inode_length (file->inode);
}

/* Sets the current position in FILE to NEW_POS bytes from the
 * start of the file. */
void
file_seek (struct file *file, off_t new_pos) {
	ASSERT (file != NULL);
	ASSERT (new_pos >= 0);
	file->pos = new_pos;
}

/* Returns the current position in FILE as a byte offset from the
 * start of the file. */
off_t
file_tell (struct file *file) {
	ASSERT (file != NULL);
	return file->pos;
}
