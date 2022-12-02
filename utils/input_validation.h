#include <linux/kernel.h>
#include "data_structures/linked_list.h"
#include <linux/string.h>

#ifndef INPUT_VALIDATION_H_
#define INPUT_VALIDATION_H_

#define TRUE 1
#define FALSE 0

int is_valid_port(int port);
int is_valid_pid(int pid);
//int is_unique_entry(char *name, linked_list_node_t *head);

int is_valid_port(int port) {
    if (port >= 0 && port <= 65536) {
        return TRUE;
    } else {
        printk(KERN_ERR "serial_killer: Invalid port!");
        return FALSE;
    }
}

int is_valid_pid(int pid) {

    if (pid >= 0 && pid <= 99999) {
        return TRUE;
    } else {
        printk(KERN_ERR "serial_killer: Invalid PID!");
        return FALSE;
    }
}

int is_unique_entry(char *name, linked_list_node_t *head){
    linked_list_node_t *curr = head;
    while (curr != NULL) {
        if (strncmp(curr->name, name, MAX_CHAR) == 0) {
            printk(KERN_ERR "serial_killer: Found duplicate entry - %s\n", curr->name);
            return FALSE;
        }
        curr = curr->next;
    }
    return TRUE;
}
#endif