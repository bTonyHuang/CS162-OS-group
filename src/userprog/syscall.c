#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "threads/malloc.h"
#include "filesys/file.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

static void syscall_handler(struct intr_frame*);
struct file* find_file(struct process* p, int fd);
int add_file(struct file* new_file);
bool valid_address(void* uaddr);
bool valid_pointer(void* ptr, size_t size);
bool valid_string(char* ustr);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);
  int fd;

  // bool valid_ptr = valid_pointer(args, 4);
  // if (!valid_ptr) {
  //   f->eax = -1;
  //   process_exit();
  // }

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  /* printf("System call number: %d\n", args[0]); */
  switch(args[0]){
    case SYS_EXIT:
      f->eax = args[1];
      printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
      process_exit();
      break;
    case SYS_WRITE:
      fd = args[1];
      char* buffer = (char*) args[2];
      size_t size = args[3];

      // if (buffer == NULL) {
      //   f->eax = -1;
      //   process_exit();
      //   break;
      // }

      // bool buffer_valid = valid_pointer(buffer, size);
      // if (!buffer_valid) {
      //   f->eax = -1;
      //   process_exit();
      //   break;
      // }

      // bool valid_addr = valid_address(args[2]);
      // if (!valid_addr) {
      //   f->eax = -1;
      //   process_exit();
      // }

      struct file* file_struct;

      file_struct = find_file(thread_current()->pcb, fd);
      // if (file_struct == NULL) {
      //   break; // bad fd, handle later
      // }

      if (fd == 1) {
        putbuf((void *) buffer, size);
        f->eax = size;
        break;
      }

      f->eax = file_write(file_struct, buffer, size);
      break;
    case SYS_PRACTICE:
      f->eax = args[1] + 1;
      break;
  }

  //original version
  // if (args[0] == SYS_EXIT) {
  //   f->eax = args[1];
  //   printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
  //   process_exit();
  //     reak;
  // }
}

struct file* find_file(struct process* p, int fd) {
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
  struct process* p = thread_current()->pcb;
  struct file_mapping* f = malloc(sizeof(struct file_mapping));
  f->file_struct_ptr = new_file;
  f->fd = p->num_fds++;
  list_push_back(p->fm_list, &f->elem);
  return f->fd;
}


/* Pointer validation helper functions to gracefully kill misbehaving processes. */
/* Helps to pass exit(-1) messages even if a process exits due to a fault */
bool valid_address(void* uaddr) {
  return is_user_vaddr(uaddr) && pagedir_get_page(thread_current()->pcb->pagedir, uaddr) != NULL;
}

bool valid_pointer(void* ptr, size_t size) {
  if (!valid_address(ptr) || !valid_address(ptr + size)) {
    return false;
  }
  return true;
}

bool valid_string(char* ustr) {
  if (is_user_vaddr(ustr)) {
    char* full_string = pagedir_get_page(thread_current()->pcb->pagedir, ustr);
    if (full_string != NULL && valid_address(ustr + strlen(full_string) + 1))
      return true;
  }
  return false;
}


