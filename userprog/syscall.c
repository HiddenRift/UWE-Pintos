#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "threads/malloc.h"
#include <hash.h>
#include "filesys/file.h"
#include "filesys/filesys.h"

/*****Defines*********/
#define ARG_1 4
#define ARG_2 8
#define ARG_3 12
#define MAXFILENAME 15

/*****Prototypes******/
static void syscall_handler (struct intr_frame *);

// validation function prototypes
static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);
static uint32_t load_stack(struct intr_frame *f, int offset);
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
bool file_list_uninitialised(struct hash *filesopen);
unsigned file_link_hash(const struct hash_elem *i, void *aux UNUSED);
bool page_less(const struct hash_elem *a1, const struct hash_elem *b1, void *aux UNUSED);
bool initialise_file_hash(struct hash **filesopen); //pass in by reference &
struct file_link *fd_lookup(const int fd, struct hash *open_files);
bool insert_file_link(const int fd, struct file *openedFile);
/*****Definitions****/
void
syscall_init (void)
{
  //printf("::DEBUG:: Executing SYSCALL_INIT\n");
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
        //printf("DEBUG:: loading stack with offset %d caused error :%x :\n", offset,  (unsigned)f->esp + offset);
        handle_exit(-1);
    }
    return *((uint32_t*)(f->esp + offset));
}

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


// file handling functions
// returns true if file map is uninitialised
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
    hash_insert (current->files_open, &new->hash_elem);
    return true;
}


static void
syscall_handler (struct intr_frame *f UNUSED)
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
    case SYS_WRITE:{
        //printf("<2> In SYS_WRITE: %d\n", *p);
        int fd = (int)load_stack(f, 4);
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

<<<<<<< HEAD


      //Alex Foulds
      //Ends tasks and powers down Pintos
      case SYS_HALT:
        shutdown_power_off();
=======
    case SYS_CREATE:
        f->eax = handle_create((char*)load_stack(f, 4), (unsigned)load_stack(f, 8));
        break;

    case SYS_OPEN:
        f->eax = handle_open ((char*)load_stack(f, 4));
>>>>>>> 99ab2fc69ff4b6a4a18b282767230322a43d3e87
        break;

    case SYS_CLOSE:
        handle_close((int)load_stack(f, 4));
        break;

    case SYS_FILESIZE:
        f->eax = handle_filesize((int)load_stack(f, 4));
        break;

    case SYS_TELL:
        f->eax = handle_tell((unsigned)load_stack(f, 4));
        break;

    default:
            printf("Unhandled SYSCALL(%d)\n", *p);
            thread_exit ();
            break;
  }
}


int handle_open (const char *file)
{
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
        }
    }
    if(fd == -1)
    {
        // fd is unchanged so no fd was found
        return -1;
    }
    //TODO: ADD LOCK HERE
    struct file *opened_file = filesys_open (file);
    if(opened_file == NULL)
    {
        // file cannot be opened
        return -1;
    }
    if(insert_file_link(fd, opened_file) == false)
    {
        // memory allocation failed so tidy up after ourselves
        file_close (opened_file);
        return -1;
    }
    //TODO: END LOCK HERE
    return fd;


}


void handle_close(const int fd)
{
    struct thread *current = thread_current();
    struct file_link *file_link1 = fd_lookup(fd, current->files_open);
    if(file_link1 != NULL)
    {

        //TODO: ADD LOCK HERE
        //file is opened so close it
        file_close (file_link1->fileinfo);
        // now remove from hash;
        hash_delete(current->files_open, &file_link1->hash_elem);
        //TODO: RELEASE LOCK HERE
        // and finally free filelink struct
        free(file_link1);
    }

}


int handle_filesize(const int fd)
{
    struct thread *current = thread_current();
    struct file_link *file_link1 =fd_lookup(fd, current->files_open);
    if (file_link1 == NULL)
    {
        // file isnt open// possibly kill process
        return 0;
    }
    //file exists so try getting size
    //TODO: ADD LOCK HERE
    int return_val = (int)file_length (file_link1->fileinfo);
    //TODO: RELEASE LOCK HERE
    return return_val;
}

unsigned handle_tell(const int fd)
{
    struct thread *current = thread_current();
    struct file_link *file_link1 = fd_lookup(fd, current->files_open);
    if (file_link1 == NULL)
    {
        // file isnt open// possibly kill process
        return 0;
    }
    //TODO: ADD LOCK HERE
    unsigned return_val = (unsigned)file_tell(file_link1->fileinfo);
    //TODO: RELEASE LOCK HERE
    return return_val;
}

void handle_seek(const int fd, unsigned position)
{
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
        file_seek(file_link1->fileinfo, position);
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
    if(!is_valid_filename(filename))
    {
        //invalid filename
        return false;
    }
    //filename valid attempt filecreate / return val
    return filesys_create(filename, initial_size);
}
bool
handle_remove (const char *filename)
{
    if(!is_valid_filename(filename))
    {
        //invalid filename
        return false;
    }
    //filename valid attempt filecreate / return val
    return filesys_remove(filename);
}


int
handle_write(int fd, char* buffer, unsigned size)
{
    if(!is_valid_buffer(buffer,size))
    {
        handle_exit(-1);
        return 0;
    }
    if(fd == STDOUT_FILENO)
    {
        putbuf (buffer, size);
        return size;
    }
    //TODO implement write to file
    printf("DEBUG:: Writing to files (FD:%d) not implemented yet\n",fd);
    handle_exit(-1);
    return 0;
}

int
handle_read(int fd, void* buffer, unsigned size)
{
    if(!is_valid_buffer(buffer,size))
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
    //TODO implement read from file
    printf("DEBUG:: Attempted reading from file(FD:%d)\n", fd);
    handle_exit(404);// 404 stuff not found

    //return -1 if file cannot be read for anything other than eof;
    return -1;
}

void
handle_exit(int status)
{
    struct thread *current = thread_current();
    /*
    //test hash
        // test insert
        struct file_link *new, *new2;
        new = malloc(sizeof(struct file_link));
        new->fd = 2;
        new->DEBUG = 'a';
        hash_insert (current->files_open, &new->hash_elem);

        new2 = malloc(sizeof(struct file_link));
        new2->fd = 3;
        new2->DEBUG = 'x';
        hash_insert (current->files_open, &new2->hash_elem);

        // now to find
        struct file_link *result = fd_lookup(3, current->files_open);
        if(result != NULL)
        {
            printf("%c\n",result->DEBUG);
        }else{
            printf("not found\n");
        }
        result = fd_lookup(2, current->files_open);
        if(result != NULL)
        {
            printf("%c\n",result->DEBUG);
        }else{
            printf("not found\n");
        }
        hash_delete(current->files_open, &new2->hash_elem);
    //stop test
    */

    current->exit_status = status;
    thread_exit();
}
