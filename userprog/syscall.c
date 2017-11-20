#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"

static void syscall_handler (struct intr_frame *);

static int get_user (const uint8_t *uaddr);
static uint32_t load_stack(struct intr_frame *f, int offset);

void handle_exit(int status);

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static int
get_user (const uint8_t *uaddr)
{
    int result;
    asm ("movl $1f, %0; movzbl %1, %0; 1:"
    : "=&a" (result) : "m" (*uaddr));
    return result;
}

static uint32_t
load_stack(struct intr_frame *f, int offset)
{
    // need to add check for valid address
    // i.e. user can do bad things
    if(get_user (f->esp + offset) == -1)
    {
        //TODO:
        //exit thread
    }
    return *((uint32_t*)(f->esp + offset));
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
        //do exit;
        handle_exit((int)load_stack((struct intr_frame*)p, 4));
        break;

      case SYS_HALT:
        shutdown_power_off();
        break;



    default: {
            printf("Unhandled SYSCALL(%d)\n", *p);
            thread_exit ();
            break;
    }
  }
}

void handle_exit(int status)
{
    //struct thread * current = thread_current();
    thread_exit();
}
