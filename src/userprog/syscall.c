#include "userprog/syscall.h"
#include <stdio.h>
#include <float.h>
#include <string.h>
#include <syscall-nr.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/directory.h"
#include "filesys/inode.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"

#define READDIR_MAX_LEN 14

static void syscall_handler(struct intr_frame*);
static void copy_in(void*, const void*, size_t);

void syscall_init(void) {
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* System call handler. */
static void syscall_handler(struct intr_frame* f) {
  typedef int syscall_function(int, int, int);

  /* A system call. */
  struct syscall {
    size_t arg_cnt;         /* Number of arguments. */
    syscall_function* func; /* Implementation. */
  };

  /* Table of system calls. */
  static const struct syscall syscall_table[] = {
      {0, (syscall_function*)sys_halt},
      {1, (syscall_function*)sys_exit},
      {1, (syscall_function*)sys_exec},
      {1, (syscall_function*)sys_wait},
      {2, (syscall_function*)sys_create},
      {1, (syscall_function*)sys_remove},
      {1, (syscall_function*)sys_open},
      {1, (syscall_function*)sys_filesize},
      {3, (syscall_function*)sys_read},
      {3, (syscall_function*)sys_write},
      {2, (syscall_function*)sys_seek},
      {1, (syscall_function*)sys_tell},
      {1, (syscall_function*)sys_close},
      {1, (syscall_function*)sys_practice},
      {1, (syscall_function*)sys_compute_e},
      {3, (syscall_function*)sys_pthread_create},
      {0, (syscall_function*)sys_pthread_exit},
      {1, (syscall_function*)sys_pthread_join},
      {1, (syscall_function*)sys_lock_init},
      {1, (syscall_function*)sys_lock_acquire},
      {1, (syscall_function*)sys_lock_release},
      {2, (syscall_function*)sys_sema_init},
      {1, (syscall_function*)sys_sema_down},
      {1, (syscall_function*)sys_sema_up},
      {0, (syscall_function*)sys_get_tid},
      {2, (syscall_function*)sys_mmap},
      {1, (syscall_function*)sys_munmap},
      {1, (syscall_function*)sys_chdir},
      {1, (syscall_function*)sys_mkdir},
      {2, (syscall_function*)sys_readdir},
      {1, (syscall_function*)sys_isdir},
      {1, (syscall_function*)sys_inumber},
  };

  const struct syscall* sc;
  unsigned call_nr;
  int args[3];

  /* Get the system call. */
  copy_in(&call_nr, f->esp, sizeof call_nr);
  if (call_nr >= sizeof syscall_table / sizeof *syscall_table)
    process_exit();
  sc = syscall_table + call_nr;

  if (sc->func == NULL)
    process_exit();

  /* Get the system call arguments. */
  ASSERT(sc->arg_cnt <= sizeof args / sizeof *args);
  memset(args, 0, sizeof args);
  copy_in(args, (uint32_t*)f->esp + 1, sizeof *args * sc->arg_cnt);

  /* Execute the system call,
     and set the return value. */
  f->eax = sc->func(args[0], args[1], args[2]);
}

/* Closes a file safely */
void safe_file_close(struct file* file) {
  file_close(file);
}

/* Returns true if UADDR is a valid, mapped user address,
   false otherwise. */
static bool verify_user(const void* uaddr) {
  return (uaddr < PHYS_BASE && pagedir_get_page(thread_current()->pcb->pagedir, uaddr) != NULL);
}

/* Copies a byte from user address USRC to kernel address DST.
   USRC must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static inline bool get_user(uint8_t* dst, const uint8_t* usrc) {
  int eax;
  asm("movl $1f, %%eax; movb %2, %%al; movb %%al, %0; 1:" : "=m"(*dst), "=&a"(eax) : "m"(*usrc));
  return eax != 0;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static inline bool put_user(uint8_t* udst, uint8_t byte) {
  int eax;
  asm("movl $1f, %%eax; movb %b2, %0; 1:" : "=m"(*udst), "=&a"(eax) : "q"(byte));
  return eax != 0;
}

/* Copies SIZE bytes from user address USRC to kernel address
   DST.
   Call process_exit() if any of the user accesses are invalid. */
static void copy_in(void* dst_, const void* usrc_, size_t size) {
  uint8_t* dst = dst_;
  const uint8_t* usrc = usrc_;

  for (; size > 0; size--, dst++, usrc++)
    if (usrc >= (uint8_t*)PHYS_BASE || !get_user(dst, usrc))
      process_exit();
}

/* Creates a copy of user string US in kernel memory
   and returns it as a page that must be freed with
   palloc_free_page().
   Truncates the string at PGSIZE bytes in size.
   Call process_exit() if any of the user accesses are invalid. */
static char* copy_in_string(const char* us) {
  char* ks;
  size_t length;

  ks = palloc_get_page(0);
  if (ks == NULL)
    process_exit();

  for (length = 0; length < PGSIZE; length++) {
    if (us >= (char*)PHYS_BASE || !get_user(ks + length, us++)) {
      palloc_free_page(ks);
      process_exit();
    }

    if (ks[length] == '\0')
      return ks;
  }
  ks[PGSIZE - 1] = '\0';
  return ks;

}

/* Returns the file descriptor associated with the given handle.
   Terminates the process if HANDLE is not associated with an
   open file. */
static struct file_descriptor* lookup_fd(int handle) {
  struct thread* cur = thread_current();
  struct list_elem* e;

  for (e = list_begin(&cur->pcb->fds); e != list_end(&cur->pcb->fds); e = list_next(e)) {
    struct file_descriptor* fd;
    fd = list_entry(e, struct file_descriptor, elem);
    if (fd->handle == handle)
      return fd;
  }

  process_exit();
  NOT_REACHED();
}

/*changing the current working directory*/
int sys_chdir(const char* udir) {
  char* dir_path = copy_in_string(udir);

  bool success = filesys_chdir(dir_path);

  return success;
}

/*creating a new directory*/
int sys_mkdir(const char* udir) {
  char* dir_path = copy_in_string(udir);

  return sys_file_create(dir_path, 0, true);
}

/*read one dir-entry each time, increasing pos in dir. pass . and ..*/
int sys_readdir(int handle, char name[READDIR_MAX_LEN + 1]) {
  struct file_descriptor* fd;
  fd = lookup_fd(handle);
  if (!fd->is_dir) {
    return false;
  }

  return true;
}

/* Isdir system call. */
int sys_isdir(int handle) {
  struct file_descriptor* fd;
  fd = lookup_fd(handle);
  return fd->is_dir;
}

/* Inumber system call. */
int sys_inumber(int handle) {
  struct file_descriptor* fd;
  fd = lookup_fd(handle);
  if (fd->is_dir) {
    return fd->dir->inode->sector;
  } else {
    return fd->file->inode->sector;
  }
}

/* Halt system call. */
int sys_halt(void) { shutdown_power_off(); }

/* Exit system call. */
int sys_exit(int exit_code) {
  thread_current()->pcb->wait_status->exit_code = exit_code;
  process_exit();
  NOT_REACHED();
}

/* Exec system call. */
int sys_exec(const char* ufile) {
  pid_t tid;
  char* kfile = copy_in_string(ufile);

  tid = process_execute(kfile);

  palloc_free_page(kfile);

  return tid;
}

/* Wait system call. */
int sys_wait(pid_t child) { return process_wait(child); }

/* Create system call. */
int sys_create(const char* ufile, unsigned initial_size) {
  char* kfile = copy_in_string(ufile);
  bool ok;

  ok = sys_file_create(kfile, initial_size, false);

  palloc_free_page(kfile);

  return ok;
}

/* Remove system call. */
int sys_remove(const char* ufile) {
  char* kfile = copy_in_string(ufile);
  bool ok;

  ok = filesys_remove(kfile);

  palloc_free_page(kfile);

  return ok;
}

/* Open system call. */
int sys_open(const char* ufile) {
  char* kfile = copy_in_string(ufile);
  struct file_descriptor* fd;
  int handle = -1;

  fd = malloc(sizeof *fd);
  if (fd != NULL) {
    /* for some file path /a/b/c/d/, this logic grabs the inode corresponding to entry d. */
    char filename[NAME_MAX + 1];
    struct dir* container_dir = resolve(kfile, filename);
    if (container_dir == NULL) {
      return NULL;
    }
    struct inode* inode;
    bool inode_exists = dir_lookup(container_dir, filename, &inode);
    dir_close(container_dir);
    if (!inode_exists) {
      return NULL;
    }

    /* Entry d is either a directory (sub) or a file, check its inode->is_dir, then handle appropriately. */

    fd->file = filesys_open(kfile);
    if (fd->file != NULL) {
      struct thread* cur = thread_current();
      handle = fd->handle = cur->pcb->next_handle++;
      list_push_front(&cur->pcb->fds, &fd->elem);
    } else
      free(fd);
  }

  palloc_free_page(kfile);
  return handle;
}

/* Filesize system call. */
int sys_filesize(int handle) {
  struct file_descriptor* fd = lookup_fd(handle);
  int size;
   
  size = file_length(fd->file);

  return size;
}

/* Read system call. */
int sys_read(int handle, void* udst_, unsigned size) {
  uint8_t* udst = udst_;
  struct file_descriptor* fd;
  int bytes_read = 0;

  /* Handle keyboard reads. */
  if (handle == STDIN_FILENO) {
    for (bytes_read = 0; (size_t)bytes_read < size; bytes_read++)
      if (udst >= (uint8_t*)PHYS_BASE || !put_user(udst++, input_getc()))
        process_exit();
    return bytes_read;
  }

  /* Handle all other reads. */
  fd = lookup_fd(handle);
  // if (fd->is_dir) {
  //   process_exit();
  // }
  while (size > 0) {
    /* How much to read into this page? */
    size_t page_left = PGSIZE - pg_ofs(udst);
    size_t read_amt = size < page_left ? size : page_left;
    off_t retval;

    /* Check that touching this page is okay. */
    if (!verify_user(udst)) { 
      process_exit();
    }

    /* Read from file into page. */
    retval = file_read(fd->file, udst, read_amt);
    if (retval < 0) {
      if (bytes_read == 0)
        bytes_read = -1;
      break;
    }
    bytes_read += retval;

    /* If it was a short read we're done. */
    if (retval != (off_t)read_amt)
      break;

    /* Advance. */
    udst += retval;
    size -= retval;
  }

  return bytes_read;
}

/* Write system call. */
int sys_write(int handle, void* usrc_, unsigned size) {
  uint8_t* usrc = usrc_;
  struct file_descriptor* fd = NULL;
  int bytes_written = 0;

  /* Lookup up file descriptor. */
  if (handle != STDOUT_FILENO)
    fd = lookup_fd(handle);
    // if (fd->is_dir) {
    //   process_exit();
    // }

  while (size > 0) {
    /* How much bytes to write to this page? */
    size_t page_left = PGSIZE - pg_ofs(usrc);
    size_t write_amt = size < page_left ? size : page_left;
    off_t retval;

    /* Check that we can touch this user page. */
    if (!verify_user(usrc)) {
      process_exit();
    }

    /* Do the write. */
    if (handle == STDOUT_FILENO) {
      putbuf(usrc, write_amt);
      retval = write_amt;
    } else
      retval = file_write(fd->file, usrc, write_amt);
    if (retval < 0) {
      if (bytes_written == 0)
        bytes_written = -1;
      break;
    }
    bytes_written += retval;

    /* If it was a short write we're done. */
    if (retval != (off_t)write_amt)
      break;

    /* Advance. */
    usrc += retval;
    size -= retval;
  }

  return bytes_written;
}

/* Seek system call. */
int sys_seek(int handle, unsigned position) {
  struct file_descriptor* fd = lookup_fd(handle);
  if ((off_t)position >= 0)
    file_seek(fd->file, position);
  return 0;
}

/* Tell system call. */
int sys_tell(int handle) {
  struct file_descriptor* fd = lookup_fd(handle);
  unsigned position;

  position = file_tell(fd->file);

  return position;
}

/* Close system call. */
int sys_close(int handle) {
  struct file_descriptor* fd = lookup_fd(handle);
  safe_file_close(fd->file);
  list_remove(&fd->elem);
  free(fd);
  return 0;
}

/* Practice system call. */
int sys_practice(int input) { return input + 1; }

/* Compute e and return a float cast to an int */
int sys_compute_e(int n) { return sys_sum_to_e(n); }

/* Dummy syscall. */
int sys_mmap(int handle UNUSED, void* addr UNUSED) {
  return 0;
}

/* Dummy syscall. */
void sys_munmap(int mapid UNUSED) {
  return;
}

int sys_pthread_create(stub_fun sfun UNUSED, pthread_fun tfun UNUSED, const void* arg UNUSED) {
  return 0;
}

int sys_pthread_exit(void) {
  return 0;
}

int sys_pthread_join(int tid UNUSED) {
  return tid;
}

int sys_lock_init(char* lock_ptr UNUSED) {
  return 0;
}

int sys_lock_acquire(char* lock_ptr UNUSED) {
  return 0;
}

int sys_lock_release(char* lock_ptr UNUSED) {
  return 0;
}

int sys_sema_init(char* sema_ptr UNUSED, int val UNUSED) {
  return 0;
}

int sys_sema_down(char* sema_ptr UNUSED) {
  return 0;
}

int sys_sema_up(char* sema_ptr UNUSED) {
  return 0;
}

int sys_get_tid(void) {
  return 0;
}