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
MODULE_AUTHOR("Camilo Andres Disidoro");

// Declaracion de la estructura base
struct list_head mylist;  // Cabecera de la lista enlazada
struct list_item {  // Estructura representativa de los nodos de la lista
    int data;
    struct list_head links;
};

// Funciones de eliminacion de datos y limpieza de la lista

static void list_cleanup(void) {
    struct list_head* cur_node = NULL;
    struct list_head* next = NULL;
    struct list_item* item = NULL;
    if (!list_empty(&mylist)) {
        trace_printk("Cleaning modlist\n");
        list_for_each_safe(cur_node, next, &mylist) {
            item = list_entry(cur_node, struct list_item, links);
            list_del(cur_node);
            kfree(item);
        }
    }else{
        trace_printk("List is currently empty!\n");
    }
}

static void remove_item(int val){
    struct list_head* cur_node = NULL;
    struct list_head* next = NULL;
    struct list_item* item = NULL;
    if (!list_empty(&mylist)) {
        trace_printk("Removing %i from modlist\n", val);
        list_for_each_safe(cur_node, next, &mylist) {
            item = list_entry(cur_node, struct list_item, links);
            if(item->data == val){
                list_del(cur_node);
                kfree(item);
            }
        }
    }else{
        trace_printk("List is currently empty!\n");
    }
}

// Funciones de lectura y escritura del modulo

static ssize_t modlist_read(struct file *filp, char __user *buf, size_t len, loff_t *off) {
    char* lbuf = kmalloc(1024, GFP_KERNEL);
    int nr_bytes = 0, offset;
    char *out = lbuf;
    struct list_item* item = NULL;
    struct list_head* cur_node = NULL;

    trace_printk("Reading modlist\n");

    if ((*off) > 0) {// No hay nada mas pendiente de leer
        kfree(lbuf);
        return 0;
    }

    list_for_each(cur_node, &mylist) {
        item = list_entry(cur_node, struct list_item, links);
        trace_printk("Iteration of list_for_each with value %d\n", item->data);
        offset = sprintf(out, "%d\n", item->data);
        if(nr_bytes + offset > 1024){
            trace_printk("Memory limit reached\n");
        }else{
            nr_bytes += offset;
            out += offset;
        }
    }

    // Transfiere informacion del kernel al espacio de usuario
    if (copy_to_user(buf, lbuf, nr_bytes)) {
        kfree(lbuf);
        return -EINVAL;
    }
    
    (*off) += len;  // Actualiza el puntero de fichero
    kfree(lbuf);
    return nr_bytes; 
}

static ssize_t modlist_write(struct file *filp, const char __user *buf, size_t len, loff_t *off) {
    int val; //Valor numerico que se va a agregar a la lista
    char* wbuf = kmalloc (1024, GFP_KERNEL);
    struct list_item *item;
    if ((*off) > 0) {  // La aplicacion puede escribir en esta entrada solo una vez
        kfree(wbuf);
        return 0;
    }
    // Transifere datos desde espacio usuario a espacio kernel
    if (copy_from_user(&wbuf[0], buf, len)) {
        kfree(wbuf);
        return -EFAULT;
    }
    wbuf[len] = '\0';
    trace_printk("New value of wbuf: %s\n", wbuf);

    //Se comprueba que accion se ha solicitado
    if(sscanf(wbuf, "add %i", &val) == 1){
        trace_printk("Accessing add to linked list\n");
        trace_printk("Value tracked, %d\n", val);
        item = (struct list_item*)kmalloc(sizeof(struct list_item), GFP_KERNEL);
        item->data = val;
        list_add_tail(&item->links,&mylist);
    }else if(sscanf(wbuf, "remove %i", &val) == 1){
        trace_printk("Accessing remove to linked list\n");
        trace_printk("Value tracked, %d\n", val);
        remove_item(val);
    }else if(strcmp(wbuf, "cleanup\n") == 0){
        trace_printk("Accessing cleanup linked list\n");
        list_cleanup();
        INIT_LIST_HEAD(&mylist);
    }else{
        trace_printk("Bad action requested\n");
        kfree(wbuf);
        return -EINVAL;
    }
    kfree(wbuf);
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
    proc_entry = proc_create( "modlist", 0666, NULL, &proc_entry_fops);
    if (proc_entry == NULL) {
        ret = -ENOMEM;
        printk(KERN_INFO "Modlist: Can't create /proc entry\n");
    } else {
        printk(KERN_INFO "Modlist: Module loaded\n");
    }
    return ret;
}

void exit_modlist_module(void){
    remove_proc_entry("modlist", NULL);
    list_cleanup();
    printk(KERN_INFO "Modlist: Module unloaded.\n");
}

// Enlazado de las funciones de carga/descarga
module_init(init_modlist_module);
module_exit(exit_modlist_module);
