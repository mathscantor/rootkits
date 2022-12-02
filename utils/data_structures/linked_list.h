#include <linux/kernel.h>

#ifndef LINKED_LIST_NODE_H_
#define LINKED_LIST_NODE_H_

#define MAX_CHAR 6
typedef struct linked_list_node{
    char name[MAX_CHAR];
    struct linked_list_node *next;
} linked_list_node_t;

linked_list_node_t* add_node(linked_list_node_t *head_node, char *name, int list_len);
linked_list_node_t* remove_node(linked_list_node_t *head_node, char *name, int list_len);
void free_nodes(linked_list_node_t *head_node);
void printk_nodes(linked_list_node_t *head_node);
int get_linked_list_len(linked_list_node_t *head_node);

linked_list_node_t* add_node(linked_list_node_t* head_node, char *name, int list_len) {
    linked_list_node_t *new_node;
    new_node = kzalloc(sizeof(linked_list_node_t), GFP_KERNEL);
    strncpy(new_node->name, name, MAX_CHAR);
    new_node->next = NULL;
    if (list_len == 0){
        head_node = new_node;
    } else {
        linked_list_node_t *curr_node = head_node;
        while (curr_node != NULL) {
            if (curr_node->next == NULL) {
                curr_node->next = new_node;
                break;
            }
            curr_node = curr_node->next;
        }
    }
    return head_node;
}

linked_list_node_t* remove_node(linked_list_node_t *head_node, char *name, int list_len) {
    linked_list_node_t *curr_node = head_node;
    linked_list_node_t *prev_node = curr_node;

    // If list in empty, just return back the head_node
    if (list_len == 0) {
        return head_node;
    }

    while (curr_node != NULL) {
        if ((memcmp(curr_node->name, name, MAX_CHAR) == 0)) {
            if (curr_node == head_node) {
                head_node = curr_node->next;
            } else {
                prev_node->next = curr_node->next;
            }
            kfree(curr_node);
            return head_node;
        }
        prev_node = curr_node;
        curr_node = curr_node->next;
    }
    return head_node;
}

void free_nodes(linked_list_node_t *head_node) {
    linked_list_node_t *curr_node = head_node;
    while (curr_node != NULL) {
        // Move the head_proc to the next node before freeing the current.
        head_node = curr_node->next;
        kfree(curr_node);
        curr_node = head_node;
    }
}

void printk_nodes(linked_list_node_t *head_node) {
    linked_list_node_t *curr_node = head_node;
    while (curr_node != NULL)
    {
        printk(KERN_CONT "%s ", curr_node->name);
        curr_node = curr_node->next;
    }
    printk(KERN_CONT "\n");
}

int get_linked_list_len(linked_list_node_t *head_node) {

    int size = 0;

    linked_list_node_t *curr_node = head_node;
    while (curr_node != NULL) {
        size++;
        curr_node = curr_node->next;
    }
    return size;
}

int is_present_in_linked_list(char *name, linked_list_node_t *head_node) {
    linked_list_node_t *curr = head_node;
    while (curr != NULL) {
        if (strncmp(curr->name, name, MAX_CHAR) == 0) {
            return 1;
        }
        curr = curr->next;
    }
    return 0;
}
#endif

