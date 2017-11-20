#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}


static void
syscall_handler (struct intr_frame *f UNUSED)
{
  //system calls go here
  uint32_t *p = f->esp;
  //printf ("DEBUG:: in system call: system call number: %d\n", *p);

  switch (*p) {
    case SYS_WRITE:{
        //add by lsc working
        //printf("<2> In SYS_WRITE: %d\n", *p);
        int fd = *(int *)(f->esp +4);
        void *buffer = *(char**)(f->esp + 8);
        unsigned size = *(unsigned *)(f->esp + 12);
        //int written_size = process_write(fd, buffer, size);
        putbuf (buffer, size);
        int written_size = size;
        f->eax = written_size;
        break;

      }


      case SYS_EXIT:
        //do nothing;

    default: {
            printf("Unhandled SYSCALL(%d)\n", *p);
            thread_exit ();
            break;
    }
  }
}

