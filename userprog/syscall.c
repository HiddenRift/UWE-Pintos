#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"

/*****Defines*********/
#define ARG_1 4
#define ARG_2 8
#define ARG_3 12

/*****Prototypes******/
static void syscall_handler (struct intr_frame *);

// validation function prototypes
static int get_user (const uint8_t *uaddr);
static uint32_t load_stack(struct intr_frame *f, int offset);

// system call prototypes
void handle_exit(int status);

/*****Definitions****/
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
        //TODO: pass in correct error
        handle_exit(-1);
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
        //printf("<2> In SYS_WRITE: %d\n", *p);
        UNUSED int fd = (int)load_stack(f, 4);
        void *buffer = (char*)load_stack(f, 8);
        unsigned size = (unsigned)load_stack(f, 12);
        //int written_size = process_write(fd, buffer, size);
        putbuf (buffer, size);
        int written_size = size;
        f->eax = written_size;
        break;
    }
    case SYS_EXIT:
        //do exit;
        handle_exit((int)load_stack(f, 4));
        break;

    case SYS_HALT:
        shutdown_power_off();
        break;

    default:
            printf("Unhandled SYSCALL(%d)\n", *p);
            thread_exit ();
            break;
  }
}

void handle_exit(int status)
{
    //struct thread * current = thread_current();
    thread_exit();
}
