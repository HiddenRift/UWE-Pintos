#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "threads/malloc.h"
#include <hash.h>
#include "filesys/file.h"
#include "filesys/filesys.h"

/*****Defines*********/
#define SYSCALLARG1 4
#define SYSCALLARG2 8
#define SYSCALLARG3 12
#define MAXFILENAME 15

/*****Prototypes******/
static void syscall_handler (struct intr_frame *);

// validation function prototypes
static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);
static uint32_t load_stack(struct intr_frame *arg_container, int offset);
static bool is_below_PHYS_BASE(const uint8_t *uaddr);
bool is_valid_filename(const char *filename);
bool is_valid_buffer(const char *buffer, size_t size);

// system call prototypes
void handle_exit(int status);
int handle_write(int fd, char* buffer, unsigned size);
int handle_read(int fd, void* buffer, unsigned size);
bool handle_create(const char* filename, unsigned initial_size);
bool handle_remove (const char *filename);
int handle_open (const char *file);
void handle_close(const int fd);
int handle_filesize(const int fd);
unsigned handle_tell(const int fd);
void handle_seek(const int fd, unsigned position);

//file handleing prototypes
void close_remaining_files(void);
bool file_list_uninitialised(struct hash *filesopen);
unsigned file_link_hash(const struct hash_elem *i, void *aux UNUSED);
bool page_less(const struct hash_elem *a1, const struct hash_elem *b1, void *aux UNUSED);
bool initialise_file_hash(struct hash **filesopen); //pass in by reference &
struct file_link *fd_lookup(const int fd, struct hash *open_files);
bool insert_file_link(const int fd, struct file *openedFile);
void deallocate_file_link(struct hash_elem *hashtodelete, void *aux UNUSED);

// File lock used to maintain sync when accessing the filesystem
static struct semaphore file_lock;

/*
use following to aquire lock for a thread:
sema_down (&file_lock);
and the following to remove a threads lock:
sema_up (&file_lock);
*/

/*****Definitions****/

/*  initialises system call handler and file
    handling semaphore */
void
syscall_init (void)
{
  //printf("::DEBUG:: Executing SYSCALL_INIT\n");
  sema_init (&file_lock, 1);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* Reads a byte at user virtual address UADDR.
UADDR must be below PHYS_BASE.
Returns the byte value if successful, -1 if a segfault
occurred. */
static int
get_user (const uint8_t *uaddr)
{
    if(!is_below_PHYS_BASE(uaddr))
    {
        return -1;
    }
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

/*  validates that a pointer is below PHYS base
    This function is used to extend the functionality
    of put_user and get_user */
static bool
is_below_PHYS_BASE(const uint8_t *uaddr)
{
    //PHYS_BASE not in this file so used this to make it work
    //TODO: link phys base here directly instead
    return uaddr < (uint8_t*)0xC0000000;
}

/*  Validates a pointer on the stack before returning it
    This function was originally provided in syscall.c~
    but has been edited to extend its functionality */
static uint32_t
load_stack(struct intr_frame *arg_container, int offset)
{
    /*  need to add check for valid address
        i.e. user can do bad things */
    if(get_user (arg_container->esp + offset) == -1)
    {
        //printf("DEBUG:: loading stack with offset %d caused error :%x :\n", offset,  (unsigned)f->esp + offset);
        handle_exit(-1);
    }
    return *((uint32_t*)(arg_container->esp + offset));
}

/*  tests whether a filename is valid string and
    whether it exists in memory that can be legally accessed */
bool
is_valid_filename(const char *filename)
{
    for (size_t i = 0; i < MAXFILENAME; i++)
    {
        if (get_user((uint8_t*)(filename+i)) != -1)
        {
            // no segv so test for /0 char;
            if(*(filename+i) == '\0')
            {
                return true;
            }
        }
        else
        {
            //segv occurred
            return false;
        }
    }
    //reached end of loop without null terminator
    return false;
}

/*  tests whether a buffer exists in memory
    that can be legally accessed */
bool is_valid_buffer(const char *buffer, size_t size)
{
    for (size_t i = 0; i < size; i++)
    {
        if(get_user((uint8_t*)buffer+i) == -1)
        {
            return false;
        }
    }
    return true;
}


/* file handling functions
   returns true if file map is uninitialised */
bool
file_list_uninitialised(struct hash *filesopen)
{
    return filesopen == NULL;
}

unsigned
file_link_hash(const struct hash_elem *i, void *aux UNUSED)
{
    const struct file_link *p = hash_entry (i, struct file_link, hash_elem);
    return hash_int(p->fd);
}

bool
page_less(const struct hash_elem *a1, const struct hash_elem *b1, void *aux UNUSED)
{
    const struct file_link *a = hash_entry (a1, struct file_link, hash_elem);
    const struct file_link *b = hash_entry (b1, struct file_link, hash_elem);
    return a->fd < b->fd;
}

bool
initialise_file_hash(struct hash **filesopen)
{
    struct hash *temp;
    temp = malloc(sizeof(struct hash));
    *filesopen = temp;
    return hash_init (temp, file_link_hash, page_less, NULL);
}

struct file_link
*fd_lookup(const int fd, struct hash *open_files)
{
    struct file_link tolookfor;
    struct hash_elem *e;
    tolookfor.fd = fd;
    e = hash_find(open_files, &tolookfor.hash_elem);
    return (e != NULL)?hash_entry(e,struct file_link, hash_elem) : NULL;
}

bool insert_file_link(const int fd, struct file *openedFile)
{
    struct thread *current = thread_current();
    struct file_link *new;
    new = malloc(sizeof(struct file_link));
    if(new == NULL)
    {
        return false;
    }
    new->fd = fd;
    new->fileinfo = openedFile;

    /*
    lock is needed when inserting to hash as it performs no internal
    synchronisation itself so needs assistance during inserts and deletions.
    */
    sema_down (&file_lock);
    hash_insert (current->files_open, &new->hash_elem);
    sema_up (&file_lock);
    return true;
}

void
deallocate_file_link(struct hash_elem *hashtodelete, void *aux UNUSED)
{
    struct file_link *file_link1 = hash_entry(hashtodelete,struct file_link, hash_elem);
    sema_down (&file_lock);
    file_close (file_link1->fileinfo);
    sema_up (&file_lock);
    free(file_link1);
    return;
}

void
close_remaining_files(void)
{
    struct thread *current = thread_current();
    hash_destroy (current->files_open, deallocate_file_link);
    free(current->files_open);
}



static void
syscall_handler (struct intr_frame *f)
{
  //system calls go here
  struct thread *current = thread_current();
  // if files open unninitialised
  if(current->files_open == NULL)
  {
      if(initialise_file_hash(&(current->files_open)) == false)
        handle_exit(-1);
  }


  uint32_t *p = f->esp;
  //printf ("DEBUG:: in system call: system call number: %d\n", *p);

  switch (*p) {
    case SYS_WRITE:
        f->eax = handle_write((int)load_stack(f, SYSCALLARG1), (char*)load_stack(f, SYSCALLARG2), (unsigned)load_stack(f, SYSCALLARG3));
        break;

    case SYS_EXIT:
        //do exit;
        handle_exit((int)load_stack(f, SYSCALLARG1));
        break;

    case SYS_HALT:
        shutdown_power_off();
        break;

    case SYS_READ:
        f->eax = handle_read((int)load_stack(f, SYSCALLARG1), (char*)load_stack(f, SYSCALLARG2), (unsigned)load_stack(f, SYSCALLARG3));
        break;

    case SYS_CREATE:
        f->eax = handle_create((char*)load_stack(f, SYSCALLARG1), (unsigned)load_stack(f, SYSCALLARG2));
        break;

    case SYS_OPEN:
        f->eax = handle_open ((char*)load_stack(f, SYSCALLARG1));
        //99ab2fc69ff4b6a4a18b282767230322a43d3e87
        break;

    case SYS_CLOSE:
        handle_close((int)load_stack(f, SYSCALLARG1));
        break;

    case SYS_FILESIZE:
        f->eax = handle_filesize((int)load_stack(f, SYSCALLARG1));
        break;

    case SYS_TELL:
        f->eax = handle_tell((unsigned)load_stack(f, SYSCALLARG1));
        break;

    case SYS_REMOVE:
        f->eax=handle_remove((char*)load_stack(f, SYSCALLARG1));
        break;

    case SYS_SEEK:
        handle_seek((int)load_stack(f, SYSCALLARG1), (unsigned)load_stack(f, SYSCALLARG2));
        break;

    //case SYS_WAIT:
        //break;

    //case SYS_EXEC:
        //break;

    default:
            printf("Unhandled SYSCALL(%d)\n", *p);
            handle_exit(-1);
            break;
  }
}



int handle_open (const char *file)
{
    //printf("executing open\n");
    //validate filename
    struct thread *current = thread_current();
    if(!is_valid_filename(file))
    {
        return -1;
    }
    //find unnoccupied fd after 2
    int fd = -1;
    for (int potential_fd = 2; potential_fd > 1; potential_fd++)
    {
        if(fd_lookup(potential_fd, current->files_open) == NULL)
        {
            //potfd is free/
            fd = potential_fd;
            //we can now break out of loop
            break;
        }
    }
    if(fd == -1)
    {
        // fd is unchanged so no fd was found
        return -1;
    }
    sema_down (&file_lock);
    struct file *opened_file = filesys_open (file);
    sema_up (&file_lock);
    if(opened_file == NULL)
    {
        // file cannot be opened so release lock and return error val
        return -1;
    }
    if(insert_file_link(fd, opened_file) == false)
    {
        // memory allocation failed so tidy up after ourselves, release lock and return error val
        sema_down (&file_lock);
        file_close (opened_file);
        sema_up (&file_lock);
        return -1;
    }

    return fd;
}


void handle_close(const int fd)
{
    //printf("executing handle_close\n");
    if (fd == STDIN_FILENO || fd == STDOUT_FILENO)
    {
        handle_exit(-1);
    }
    struct thread *current = thread_current();
    struct file_link *file_link1 = fd_lookup(fd, current->files_open);
    if(file_link1 != NULL)
    {

        sema_down (&file_lock);
        //file is opened so close it
        file_close (file_link1->fileinfo);
        // now remove from hash;
        hash_delete(current->files_open, &file_link1->hash_elem);
        sema_up (&file_lock);
        // and finally free filelink struct
        free(file_link1);
    }

}


int handle_filesize(const int fd)
{
    //printf("executing handle_filesize\n");

    struct thread *current = thread_current();
    struct file_link *file_link1 =fd_lookup(fd, current->files_open);
    if (file_link1 == NULL)
    {
        // file isnt open// possibly kill process
        return 0;
    }
    //file exists so try getting size
    sema_down (&file_lock);
    int return_val = (int)file_length (file_link1->fileinfo);
    sema_up (&file_lock);
    return return_val;
}

unsigned handle_tell(const int fd)
{
    //printf("executing handle tell\n");
    struct thread *current = thread_current();
    struct file_link *file_link1 = fd_lookup(fd, current->files_open);
    if (file_link1 == NULL)
    {
        // file isnt open// possibly kill process
        return 0;
    }
    sema_down (&file_lock);
    unsigned return_val = (unsigned)file_tell(file_link1->fileinfo);
    sema_up (&file_lock);
    return return_val;
}

void handle_seek(const int fd, unsigned position)
{
    //printf("executing handle seek\n");
    struct thread *current = thread_current();
    struct file_link *file_link1 = fd_lookup(fd, current->files_open);
    if (file_link1 == NULL)
    {
        // file isnt open// possibly kill process
        handle_exit(-1);
        return;
    }

    if(position < (unsigned)file_length(file_link1->fileinfo))
    {
        // valid
        sema_down (&file_lock);
        file_seek(file_link1->fileinfo, position);
        sema_up (&file_lock);
    }
    else
    {
        // position out of bounds
        handle_exit(-1);
    }
    return;
}


bool
handle_create(const char* filename, unsigned initial_size)
{
    //printf("executing handle create\n");
    if(!is_valid_filename(filename))
    {
        //invalid filename
        return false;
    }
    //filename valid attempt filecreate / return val
    sema_down (&file_lock);
    bool return_val = filesys_create(filename, initial_size);
    sema_up (&file_lock);

    return return_val;
}

bool
handle_remove (const char *filename)
{
    //printf("executing handle remove\n");
    if(!is_valid_filename(filename))
    {
        //invalid filename
        return false;
    }
    //filename valid attempt fileremove / return val
    sema_down (&file_lock);
    bool return_val = filesys_remove(filename);
    sema_up (&file_lock);

    return return_val;
}


int
handle_write(int fd, char* buffer, unsigned size)
{
    //printf("executing handle write\n");
    /*  if buffer is invalid or attempting write to
        stdin Kill process */
    if(!is_valid_buffer(buffer,size) || fd == STDIN_FILENO)
    {
        handle_exit(-1);
        return 0;
    }
    if(fd == STDOUT_FILENO)
    {
        putbuf (buffer, size);
        return size;
    }

    //get file from fd and check if it exists
    struct thread *current = thread_current();
    struct file_link *file_link1 = fd_lookup(fd, current->files_open);
    if (file_link1 == NULL)
    {
        // file isnt open// kill process
        handle_exit(-1);
        return 0;
    }
    sema_down (&file_lock);
    off_t bytes_written = file_write (file_link1->fileinfo, buffer, (off_t)size);
    sema_up (&file_lock);

    return bytes_written;
}

int
handle_read(int fd, void* buffer, unsigned size)
{
    //printf("executing handle read\n");
    /*  if buffer is invalid or attempting read from
        stdout Kill process */
    if(!is_valid_buffer(buffer,size) || fd == STDOUT_FILENO)
    {
        handle_exit(-1);
        return 0;
    }
    if(fd == STDIN_FILENO)
    {
        //printf("DEBUG:: READING FROM KEYBOARD\n");
        size_t i;
        for (i = 0; i < size; i++) {
            if (!put_user(buffer+i, input_getc()))
            {
                // if put_user detects segfault  exit with exception;
                handle_exit(-1);
                break;
            }
        }
        return i;
    }
    //get file from fd and check if it exists
    struct thread *current = thread_current();
    struct file_link *file_link1 = fd_lookup(fd, current->files_open);
    if (file_link1 == NULL)
    {
        // file isnt open// kill process
        handle_exit(-1);
        return 0;
    }
    sema_down (&file_lock);
    off_t bytes_written = file_read (file_link1->fileinfo, buffer, (off_t)size);
    sema_up (&file_lock);

    return bytes_written;
}

void
handle_exit(int status)
{
    //printf("executing handle exit\n");
    struct thread *current = thread_current();
    if (current->files_open != NULL)
    {
        // if filesopen is not null then empty it and deallocate memory
        close_remaining_files();
    }

    current->exit_status = status;
    thread_exit();
}
