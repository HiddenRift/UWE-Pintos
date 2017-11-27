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
static bool put_user (uint8_t *udst, uint8_t byte);
static uint32_t load_stack(struct intr_frame *f, int offset);
static bool is_below_PHYS_BASE(const uint8_t *uaddr);

// system call prototypes
void handle_exit(int status);
int handle_write(int fd, char* buffer, unsigned size);
int handle_read(int fd, void* buffer, unsigned size);

/*****Definitions****/
void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* Reads a byte at user virtual address UADDR.
UADDR must be below PHYS_BASE.
Returns the byte value if successful, -1 if a segfault
occurred. */
static int
get_user (const uint8_t *uaddr)
{
    int result;
    asm ("movl $1f, %0; movzbl %1, %0; 1:"
         : "=&a" (result) : "m" (*uaddr));
    return result;
}

/* Writes BYTE to user address UDST.
UDST must be below PHYS_BASE.
Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
    if(!is_below_PHYS_BASE(udst))
    {
        // if not below phys base return segfault
        return 0;
    }
    int error_code;
    asm ("movl $1f, %0; movb %b2, %1; 1:"
         : "=&a" (error_code), "=m" (*udst) : "q" (byte));
    return error_code != -1;
}

static bool
is_below_PHYS_BASE(const uint8_t *uaddr)
{
    //PHYS_BASE not in this file so used this to make it work
    //TODO: link phys base here directly instead
    return uaddr < (uint8_t*)0xC0000000;
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
        f->eax = handle_write(fd, buffer, size);
        break;
    }
    case SYS_EXIT:
        //do exit;
        handle_exit((int)load_stack(f, 4));
        break;

    case SYS_HALT:
        shutdown_power_off();
        break;

    case SYS_READ:
        f->eax = handle_read((int)load_stack(f, 4), (char*)load_stack(f, 8), (unsigned)load_stack(f, 12));
        break;

    default:
            printf("Unhandled SYSCALL(%d)\n", *p);
            thread_exit ();
            break;
  }
}

int
handle_write(int fd, char* buffer, unsigned size)
{
    if(fd == STDOUT_FILENO)
    {
        putbuf (buffer, size);
        return size;
    }
    //TODO implement write to file
    printf("DEBUG:: Writing to files (FD:%d) not implemented yet\n",fd);
    thread_exit();
    return 0;
}

int
handle_read(int fd, void* buffer, unsigned size)
{
    if(fd == STDIN_FILENO)
    {
        printf("READ FROM KEYBOARD");
    }
    //TODO implement read from file
    printf("DEBUG:: Attempted reading from file(FD:%d)\n", fd);
    thread_exit();

    //return -1 if file cannot be read for anything other than eof;
    return -1;
}

void
handle_exit(int status)
{
    struct thread *current = thread_current();
    current->exit_status = status;
    thread_exit();
}
