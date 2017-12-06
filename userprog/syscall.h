#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <hash.h>
void syscall_init (void);

struct file_link{
    struct hash_elem hash_elem;
    int fd;
    struct file *fileinfo;
};

#endif /* userprog/syscall.h */
