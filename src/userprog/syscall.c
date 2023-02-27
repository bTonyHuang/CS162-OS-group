#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"

#include "filesys/file.h"

static void syscall_handler(struct intr_frame*);
struct file* find_file(struct process* p, int fd);
int add_file(struct file* new_file);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

struct file* find_file(struct process* p, int fd) {
  file_mapping_list* fm_list_ptr = p->fm_list;
  struct list_elem* iter;
  struct file_mapping* temp;

  // int length = list_size(fm_list_ptr);
  // printf("length of fd list %d\n", length);

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
  list_push_back(&p->file_mapping_list, &f->elem);
  return f->fd;
}

bool valid_address(void* uaddr) {
  return is_user_vaddr(uaddr) && pagedir_get_page(thread_current()->pcb->pagedir, uaddr) != NULL;
}

void check_ptr(void* ptr, size_t size) {
  if (!valid_address(ptr) || !valid_address(ptr + size)) {
    process_exit();
  }
}

void check_string(char* ustr) {
  if (is_user_vaddr(ustr)) {
    char* full_string = pagedir_get_page(thread_current()->pcb->pagedir, ustr);
    if (full_string != NULL && valid_address(ustr + strlen(full_string) + 1))
      return;
  }
  process_exit();
}


// void* validate_user_pointer(const void* vaddr)
// - verify the validity of a user-provided pointer, then dereference it
// - lookup_page in pagedir.c
// - pg_round_up, pg_round_down, and is_user_vaddr in vaddr.h
//     - // 
// - If ptr is invalid, call process_exit() to terminate offending process and frees its resources

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);
  int fd;
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


