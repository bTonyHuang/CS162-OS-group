#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/thread.h"
#include "userprog/process.h"

/* Argument types of sys_pthread_create. */
typedef void (*pthread_fun)(void*);
typedef void (*stub_fun)(pthread_fun, void*);

int sys_halt(void);
int sys_exit(int status);
int sys_exec(const char* ufile);
int sys_wait(pid_t child);
int sys_create(const char* ufile, unsigned initial_size);
int sys_remove(const char* ufile);
int sys_open(const char* ufile);
int sys_filesize(int handle);
int sys_read(int handle, void* udst_, unsigned size);
int sys_write(int handle, void* usrc_, unsigned size);
int sys_seek(int handle, unsigned position);
int sys_tell(int handle);
int sys_close(int handle);
int sys_practice(int input);
int sys_compute_e(int n);
int sys_pthread_create(stub_fun sfun, pthread_fun tfun, const void* arg);
int sys_pthread_exit(void);
int sys_pthread_join(int tid);
int sys_lock_init(char* lock_ptr);
int sys_lock_acquire(char* lock_ptr);
int sys_lock_release(char* lock_ptr);
int sys_sema_init(const char* ufile);
int sys_sema_down(int handle);
int sys_sema_up(int handle);
int sys_get_tid(void);


void syscall_init(void);
void safe_file_close(struct file* file);

#endif /* userprog/syscall.h */
