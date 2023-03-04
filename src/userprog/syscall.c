#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "threads/malloc.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"
#include "threads/synch.h"
#include "lib/float.h"

#define CALLOC_ASSERT(CONDITION)                                                                   \
  if (CONDITION) {                                                                                 \
  } else {                                                                                         \
    graceful_exception_exit(-1);                                                                   \
  }

static void syscall_handler(struct intr_frame*);
struct file* find_file(struct process* p, int fd);
int add_file(struct file* new_file);
bool del_file(int fd);
bool valid_pointer(void* uaddr, size_t size);
void validate_pointer(uint32_t* eax_register, void* ptr, size_t size);
bool valid_string(const char* ustr);
void graceful_exception_exit(int status);
void validate_string(const char* str);

struct lock file_operations_lock;

void syscall_init(void) {
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_operations_lock);
}

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);
  int fd;
  validate_pointer(&f->eax, args, sizeof(uint32_t));

  // printf("System call number: %d\n", args[0]); // for debugging purposes */

  switch (args[0]) {
    case SYS_EXIT: {
      /* syscall1(SYS_EXIT, status); */
      f->eax = args[1];
      printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);

      free(thread_current()->pcb->fm_list);

      /* if curr process is parent process w/ children, decrement ref_count and free/remove 
        all children/status_nodes from its cm_list if it's no longer being referenced by a process  */
      int num_child_refs = list_size(thread_current()->pcb->cm_list);
      if (num_child_refs > 0) {
        struct status_node* nodes_to_free[num_child_refs];
        child_mapping_list* cm_list_ptr = thread_current()->pcb->cm_list;
        struct list_elem* iter;
        struct status_node* temp;
        int count = 0;

        for (iter = list_begin(cm_list_ptr); iter != list_end(cm_list_ptr);
             iter = list_next(iter)) {
          temp = list_entry(iter, struct status_node, elem);
          lock_acquire(temp->status_lock);
          temp->ref_count -= 1;
          lock_release(temp->status_lock);
          if (temp->ref_count == 0) {
            nodes_to_free[count] = temp;
            count += 1;
          }
        }

        for (; count > 0; count -= 1) {
          temp = nodes_to_free[count - 1];
          free(temp->status_lock);
          free(temp);
        }
      }
      free(thread_current()->pcb->cm_list);

      /* if curr process = child process, decrement ref_count and free its status_node 
         (if it's not being referenced by parent process)
         if child is being referenced by parent, store child's exit code and notify parent of its exit */
      struct status_node* my_status = thread_current()->pcb->my_status;
      lock_acquire(my_status->status_lock);
      my_status->ref_count -= 1;
      lock_release(my_status->status_lock);

      if (my_status->ref_count == 0) {
        free(my_status->status_lock);
        free(my_status);
      } else {
        my_status->exit_status = args[1];
        sema_up(&(my_status->exit_sema));
      }

      process_exit();
    } break;
    case SYS_EXEC: {
      /* syscall1(SYS_EXEC, file) */
      validate_pointer(&f->eax, args, sizeof(uint32_t) * 2);
      validate_string((const char*)args[1]);
      /* allocate space for newly initalized lock and status_node for child 
         add new status_node to parent process's cm_list */
      struct lock* new_lock = calloc(1, sizeof(struct lock));
      CALLOC_ASSERT(new_lock != NULL);
      struct status_node* new_status = calloc(1, sizeof(struct status_node));
      CALLOC_ASSERT(new_status != NULL);

      sema_init(&(new_status->load_sema), 0);
      sema_init(&(new_status->exit_sema), 0);
      lock_init(new_lock);
      new_status->status_lock = new_lock;

      new_status->loaded = false;
      new_status->exit_status = -1;
      new_status->ref_count = 2;

      list_push_front(thread_current()->pcb->cm_list, &new_status->elem);

      /* process_execute(executable, shared status_node to child process) creates a new child process 
         parent sema downs to wait for child process to finish loading and exiting 
         before executing rest of code and returning w/ child's pid */
      pid_t cpid = process_execute((const char*)args[1], new_status);
      sema_down(&(new_status->load_sema));

      if (new_status->loaded) {
        f->eax = cpid;
        /* if child doesn't load properly, remove itself from parent's cm_list + free its status_node */
      } else {
        f->eax = -1;
        list_remove(&new_status->elem);
        free(new_status->status_lock);
        free(new_status);
      }
    } break;
    case SYS_WAIT: {
      /* syscall1(SYS_WAIT, pid); */
      int result = process_wait(args[1]);
      f->eax = result;
    } break;
    case SYS_CREATE: {
      /* bool create (const char *file, unsigned initial_size) */
      const char* file_name = (const char*)args[1];
      off_t size = (off_t)args[2];
      validate_string(file_name);
      if (size < 0) {
        graceful_exception_exit(-1);
      }

      lock_acquire(&file_operations_lock);
      f->eax = filesys_create((const char*)args[1], size);
      lock_release(&file_operations_lock);
    } break;
    case SYS_REMOVE: {
      //bool remove (const char *file)
      //validation check
      // if(!args[1]){
      //   f->eax=false;
      //   break;
      // }
      // validate_string(&f->eax, (char *)args[1]);

      lock_acquire(&file_operations_lock);
      f->eax = filesys_remove((const char*)args[1]);
      lock_release(&file_operations_lock);
    } break;
    case SYS_OPEN: {
      /* int open (const char *file) */
      //validation check
      const char* file_name = (const char*)args[1];
      validate_string(file_name);

      lock_acquire(&file_operations_lock);
      struct file* new_file = filesys_open(file_name);
      if (new_file) {
        f->eax = add_file(new_file);
      } else {
        f->eax = -1;
      }
      lock_release(&file_operations_lock);
    } break;
    case SYS_FILESIZE: {
      /* int filesize (int fd) */
      int fd = args[1];
      if (fd < 3) { //0,1,2 - stdin ...
        f->eax = -1;
        break;
      }
      lock_acquire(&file_operations_lock);

      struct file* file_struct;
      file_struct = find_file(thread_current()->pcb, fd);
      if (!file_struct) {
        f->eax =
            -1; //Returns -1 if fd does not correspond to an entry in the file descriptor table.
        break;
      }
      f->eax = file_length(file_struct);

      lock_release(&file_operations_lock);
    } break;
    case SYS_READ: {
      //int read (int fd, void *buffer, unsigned size)
      int fd = args[1];
      void* buffer = (void*)args[2];
      off_t size = (off_t)args[3];
      validate_pointer(&f->eax, buffer, size);
      if (size < 0) {
        f->eax = -1;
        break;
      }

      if (fd == STDIN_FILENO) {
        uint8_t* c = buffer;
        for (int i = 0; i != size; ++i)
          *c++ = input_getc();
        f->eax = size;
        break;
      }

      /* Before we call file_read from the library, let's check that the fd provided by the user is good. */
      file_mapping_list* fm_list_ptr = thread_current()->pcb->fm_list;
      struct list_elem* iter;
      struct file_mapping* temp;
      bool fm_exists = false;

      for (iter = list_begin(fm_list_ptr); iter != list_end(fm_list_ptr); iter = list_next(iter)) {
        temp = list_entry(iter, struct file_mapping, elem);
        if (temp->fd == fd) {
          fm_exists = true;
          break;
        }
      }

      if (!fm_exists) {
        f->eax = -1;
        break;
      }

      lock_acquire(&file_operations_lock);
      struct file* target_file = find_file(thread_current()->pcb, fd);
      if (!target_file) {
        f->eax = -1;
        lock_release(&file_operations_lock);
        break;
      }
      f->eax = file_read(target_file, buffer, size);
      lock_release(&file_operations_lock);
    } break;
    case SYS_WRITE: {
      //int write (int fd, const void *buffer, unsigned size)
      fd = args[1];
      char* buffer = (char*)args[2];
      size_t size = args[3];

      // if (fd <= 0 || fd > thread_current()->pcb->num_fds) {
      //   /* Invalid fd, error and exit process */
      //   thread_current()->pcb->my_status->exit_status = -1;
      //   process_exit();
      // }

      if (fd == STDOUT_FILENO) {
        /* Write buffer to stdout */
        putbuf((void*)buffer, size);
        f->eax = size;
      } else {
        validate_pointer(&f->eax, (void*)args[2], (size_t)args[3]);
        struct file* file = find_file(thread_current()->pcb, fd);

        if (file == NULL) {
          f->eax = -1;
        } else {
          lock_acquire(&file_operations_lock);
          f->eax = file_write(file, (void*)args[2], (off_t)args[3]);
          lock_release(&file_operations_lock);
        }
      }
    } break;
    case SYS_SEEK: {
      //void seek (int fd, unsigned position)
      int fd = args[1];
      off_t position = (off_t)args[2];
      if (fd < 3 || position < 0) {
        f->eax = -1;
        break;
      }

      lock_acquire(&file_operations_lock);
      // if (fd == 0) {
      //   //stdin
      //   file_seek(stdin,position);
      // } else if (fd == 1) {
      //   // stdout
      //   file_seek(stdout,position);
      // } else if (fd == 2) {
      //   file_seek(stderr,position);
      // } else {
      struct file* target_file = find_file(thread_current()->pcb, fd);
      if (!target_file) {
        f->eax = -1;
        lock_release(&file_operations_lock);
        break;
      }
      file_seek(target_file, position);

      lock_release(&file_operations_lock);
    } break;
    case SYS_TELL: {
      //unsigned tell(int fd)
      int fd = args[1];
      //Returns -1 if fd does not correspond to an entry in the file descriptor table.
      if (fd < 3) {
        f->eax = -1;
        break;
      }
      lock_acquire(&file_operations_lock);
      // if (fd == 0) {
      //   //stdin
      //   f->eax=file_tell(stdin);
      // } else if (fd == 1) {
      //   //stdout
      //   f->eax=file_tell(stdout);
      // } else if (fd == 2) {
      //   f->eax=file_tell(stderr);
      // } else {
      struct file* target_file = find_file(thread_current()->pcb, fd);
      if (!target_file) {
        f->eax = -1;
        lock_release(&file_operations_lock);
        break;
      }
      f->eax = file_tell(target_file);
      break;
      lock_release(&file_operations_lock);
    } break;
    case SYS_CLOSE: {
      //void close (int fd)
      int fd = args[1];
      if (fd < 3) {
        f->eax = -1;
        break;
      }

      /* To account for user calling close twice on the same fd, we need to remove the file_mapping node */
      bool fm_exists = del_file(fd);

      if (!fm_exists) {
        f->eax = -1;
        break;
      }

      lock_acquire(&file_operations_lock);
      struct file* target_file = find_file(thread_current()->pcb, fd);
      if (!target_file) {
        lock_release(&file_operations_lock);
        f->eax = -1;
        break;
      }
      file_close(target_file);
      lock_release(&file_operations_lock);

    } break;
    case SYS_PRACTICE: {
      f->eax = args[1] + 1;
    } break;
    case SYS_HALT: {
      shutdown_power_off();
    } break;

    //floating point - practice call
    case SYS_COMPUTE_E: {
      int n = (int)args[1];
      if (n < 0)
        graceful_exception_exit(-1);
      f->eax = sys_sum_to_e(n);
      break;
    }
  }
}

struct file* find_file(struct process* p, int fd) {
  if (!p) {
    return NULL;
  }
  file_mapping_list* fm_list_ptr = p->fm_list;
  struct list_elem* iter;
  struct file_mapping* temp;

  for (iter = list_begin(fm_list_ptr); iter != list_end(fm_list_ptr); iter = list_next(iter)) {
    temp = list_entry(iter, struct file_mapping, elem);
    if (temp->fd == fd) {
      return temp->file_struct_ptr;
    }
  }
  return NULL;
}

int add_file(struct file* new_file) {
  //validation check
  if (!new_file) {
    return -1;
  }
  struct process* p = thread_current()->pcb;
  struct file_mapping* f = calloc(1, sizeof(struct file_mapping));
  CALLOC_ASSERT(f != NULL);
  f->file_struct_ptr = new_file;
  f->fd = p->fd_counter;
  p->fd_counter += 1;
  list_push_back(p->fm_list, &f->elem);
  return f->fd;
}

//remove the file_mapping node
bool del_file(int fd) {
  if (fd < 0)
    return false;
  file_mapping_list* fm_list_ptr = thread_current()->pcb->fm_list;
  struct list_elem* iter;
  struct file_mapping* temp;
  bool fm_exists = false;

  for (iter = list_begin(fm_list_ptr); iter != list_end(fm_list_ptr); iter = list_next(iter)) {
    temp = list_entry(iter, struct file_mapping, elem);
    if (temp->fd == fd) {
      fm_exists = true;
      list_remove(&temp->elem);
      break;
    }
  }

  return fm_exists;
}

/* Pointer validation helper functions to gracefully kill misbehaving processes. */
/* Helps to pass exit(-1) messages even if a process exits due to a fault */
bool valid_pointer(void* uaddr, size_t size) {
  /* Make sure that the pointer doesn't leak into kernel memory */
  return is_user_vaddr(uaddr + size) &&
         pagedir_get_page(thread_current()->pcb->pagedir, uaddr + size) != NULL;
}

void validate_pointer(uint32_t* eax_register, void* ptr, size_t size) {
  if (!valid_pointer(ptr, size)) {
    *eax_register = -1;
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, -1);
    thread_current()->pcb->my_status->exit_status = -1;
    sema_up(&thread_current()->pcb->my_status->exit_sema);
    process_exit();
    NOT_REACHED();
  }
}

void graceful_exception_exit(int status) {
  thread_current()->pcb->my_status->exit_status = status;

  printf("%s: exit(%d)\n", thread_current()->pcb->process_name, status);
  sema_up(&thread_current()->pcb->my_status->exit_sema);
  process_exit();
}

bool valid_string(const char* str) {
  if (!is_user_vaddr(str)) {
    return false;
  }
  char* kernel_page_str = pagedir_get_page(thread_current()->pcb->pagedir, (void*)str);

  if (kernel_page_str == NULL) {
    return false;
  } else {
    char* final_str = (char*)str + strlen(kernel_page_str);
    if (!is_user_vaddr(final_str) ||
        pagedir_get_page(thread_current()->pcb->pagedir, final_str) == NULL) {
      return false;
    }
  }
  return true;
}

void validate_string(const char* str) {
  if (!valid_string(str)) {
    thread_current()->pcb->my_status->exit_status = -1;
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, -1);
    sema_up(&thread_current()->pcb->my_status->exit_sema);
    process_exit();
  }
}

// bool valid_pointer(void* ptr, size_t size) {
//   if (!valid_address(ptr) || !valid_address(ptr + size)) {
//     return false;
//   }
//   return true;
// }

// bool valid_string(char* ustr) {
//   if (is_user_vaddr(ustr)) {
//     char* full_string = pagedir_get_page(thread_current()->pcb->pagedir, ustr);
//     if (full_string != NULL && valid_address(ustr + strlen(full_string) + 1))
//       return true;
//   }
//   return false;
// }
