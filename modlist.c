#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/ftrace.h>
#include <linux/slab.h>
#include "list.h"

#define BUFFER_LENGTH PAGE_SIZE

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Gestion de lista enlazada de enteros");
MODULE_AUTHOR("Camilo Andres Disidoro - David Manuel Perez Mora");

// TEMPORAL
static char *command;  // Espacio reservado para el comando

// Declaracion de la estructura base
struct list_head mylist;  // Cabecera de la lista enlazada
int nr_items;
struct list_item {  // Estructura representativa de los nodos de la lista
    int data;
    struct list_head links;
};

// you want to be up here? well you got it
static void list_cleanup(struct list_head* list) {
    if (!list_empty(list)) {
        struct list_head* cur_node = NULL;
        struct list_head* next = NULL;
        list_for_each_safe(cur_node, next, list) {
            kfree(cur_node);
        }
    }
}

// Funciones de lectura y escritura del modulo TODO

static ssize_t modlist_read(struct file *filp, char __user *buf, size_t len, loff_t *off) {
  
    int nr_bytes;
    char *out;
    
    if ((*off) > 0)  // No hay nada mas pendiente de leer
        return 0;
      
    nr_bytes = nr_items * (sizeof(int) + 1);  // +1 por el '\n'
    out = (char *)kmalloc(nr_bytes + 1, GFP_KERNEL);
    trace_printk("Reserved %d bytes\n", nr_bytes);
      
    if (len < nr_bytes)
        return -ENOSPC;
    
    struct list_item* item = NULL;
    struct list_head* cur_node = NULL;
    int i = 0;

    list_for_each(cur_node, &mylist) {
        item = list_entry(cur_node, struct list_item, links);
        // replace with strcat?
        out[i] = item -> data;
        i += sizeof(int);
        out[i++] = '\n';
    }
    trace_printk("nr_bytes = %d should equal i = %d\n", nr_bytes, i);
    out[nr_bytes] = '\0';

    // Transfiere informacion del kernel al espacio de usuario
    if (copy_to_user(buf, out, nr_bytes)) {
        kfree(out);
        return -EINVAL;
    }
    
    kfree(out);
    (*off) += len;  // Actualiza el puntero de fichero
    return nr_bytes; 
}

static ssize_t modlist_write(struct file *filp, const char __user *buf, size_t len, loff_t *off) {
    int available_space = BUFFER_LENGTH - 1;
    char action[7];
    int val;
    if ((*off) > 0) {  // La aplicacion puede escribir en esta entrada solo una vez
        return 0;
    }
    if (len > available_space) {
        printk(KERN_INFO "Modlist: not enough space!!\n");
        return -ENOSPC;
    }
    // Transifere datos desde espacio usuario a espacio kernel
    if (copy_from_user(&command[0], buf, len)) {
        return -EFAULT;
    }
    sscanf(command, "%s %d", action, &val);  // Recoge los parametros que se le ha enviado al modulo
    trace_printk("New value of command: %s\n", command);
    trace_printk("Action tracked: %s\n", action);
    trace_printk("Value tracked, %d\n", val);

    if (strcmp(action, "add") == 0) {
        struct list_item *item;
        item = (struct list_item*)kmalloc(sizeof(int), GFP_KERNEL);
        struct list_head node;
        item -> data = val;
        item -> links = node;
        list_add(&node, &mylist);
    } else if (strcmp(action, "remove") == 0) {
        struct list_item *del;
        del = list_entry(&mylist, struct list_item, links);  // deletes first entry of list
    } else if (strcmp(action, "cleanup") == 0) {
        list_cleanup(&mylist);
    } else {
        trace_printk("Action not supported: %s", action);
    }

    /*
    switch (action) {
        case "add":
            break;
        case "remove":
            break;
        case "cleanup":
            break;
        default:
            break;
    }
    */
    
    command[len] = '\0';  // Agrega el `\0'
    *off += len;  // actualiza el puntero de fichero
    
    return len;
}

// Gestion del fichero /proc
static struct proc_dir_entry *proc_entry;

static const struct proc_ops proc_entry_fops = {
    .proc_read = modlist_read,
    .proc_write = modlist_write,    
};

// Carga y descarga del modulo
int init_modlist_module(void) {
    int ret = 0;
    INIT_LIST_HEAD(&mylist);
    command = (char *)vmalloc(BUFFER_LENGTH);  // TEMP
    if (!command) {
        return -ENOMEM;
    } else {
        proc_entry = proc_create( "modlist", 0666, NULL, &proc_entry_fops);
        if (proc_entry == NULL) {
            ret = -ENOMEM;
            printk(KERN_INFO "Modlist: Can't create /proc entry\n");
        } else {
            printk(KERN_INFO "Modlist: Module loaded\n");
        }
    }
    return ret;
}

void exit_modlist_module(void){
    remove_proc_entry("modlist", NULL);
    vfree(command);  // TEMP
    list_cleanup(&mylist);
    printk(KERN_INFO "Modlist: Module unloaded.\n");
}

// Enlazado de las funciones de carga/descarga
module_init(init_modlist_module);
module_exit(exit_modlist_module);