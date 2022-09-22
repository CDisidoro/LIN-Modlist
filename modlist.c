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


static char *command;  // Espacio reservado para el comando

// Declaracion de la estructura base
struct list_head mylist;  // Cabecera de la lista enlazada
int nr_items;
struct list_item {  // Estructura representativa de los nodos de la lista
    int data;
    struct list_head links;
};

// Funciones de lectura y escritura del modulo TODO


static void list_cleanup(void) {
    struct list_head* cur_node = NULL;
    struct list_head* next = NULL;
    struct list_item* item = NULL;
    if (!list_empty(&mylist)) {
        trace_printk("Cleaning modlist\n");
        list_for_each_safe(cur_node, next, &mylist) {
            item = list_entry(cur_node, struct list_item, links);
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

static ssize_t modlist_read(struct file *filp, char __user *buf, size_t len, loff_t *off) { //REVISAR, se ve con trace que recorre la lista pero no imprime datos
    int nr_bytes;
    char *out;
    struct list_item* item = NULL;
    struct list_head* cur_node = NULL;
    int i = 0;
    trace_printk("Reading modlist\n");

    if ((*off) > 0) {  // No hay nada mas pendiente de leer
        return 0;
    }
      
    nr_bytes = nr_items * (sizeof(int) + 1);  // +1 por el '\n'
    out = (char *)kmalloc(nr_bytes + 1, GFP_KERNEL);

    if (len < nr_bytes) {
        kfree(out);
        return -ENOSPC;
    }
    

    char* ptr = out;
    list_for_each(cur_node, &mylist) {
        item = list_entry(cur_node, struct list_item, links);
        trace_printk("Iteration of list_for_each with value %d\n", item->data);
        ptr += sprintf(out, "%d\n", item->data);
    }
    // ptr += sprintf(out, "\0");

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
    int val; //Valor numerico que se va a agregar a la lista
    struct list_item *item;
    if ((*off) > 0) {  // La aplicacion puede escribir en esta entrada solo una vez
        return 0;
    }
    // Transifere datos desde espacio usuario a espacio kernel
    if (copy_from_user(&command[0], buf, len)) {
        return -EFAULT;
    }
    command[len] = '\0';
    trace_printk("New value of command: %s\n", command);

    //Se comprueba que accion se ha solicitado
    if(sscanf(command, "add %i", &val) == 1){
        trace_printk("Accessing add to linked list\n");
        trace_printk("Value tracked, %d\n", val);
        item = (struct list_item*)kmalloc(sizeof(struct list_item), GFP_KERNEL);
        item->data = val;
        list_add_tail(&item->links,&mylist);
    }else if(sscanf(command, "remove %i", &val) == 1){
        trace_printk("Accessing remove to linked list\n");
        trace_printk("Value tracked, %d\n", val);
        remove_item(val);
    }else if(strcmp(command, "cleanup\n") == 0){
        trace_printk("Accessing cleanup linked list\n");
        list_cleanup();
        INIT_LIST_HEAD(&mylist);
    }else{
        trace_printk("Bad action requested\n");
        return -EINVAL;
    }

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

void exit_modlist_module(void){//Cuelga el sistema cuando hay mas de 4 nodos en la lista (Con aprox. 10 el VMWare te dice que ha explotado la MV)
    remove_proc_entry("modlist", NULL);
    vfree(command);  // TEMP
    list_cleanup();
    /*if (!list_empty(&mylist)) {
        struct list_head* cur_node = NULL;
        struct list_head* next = NULL;
        list_for_each_safe(cur_node, next, &mylist) {
            kfree(cur_node);
        }
    }*/
    printk(KERN_INFO "Modlist: Module unloaded.\n");
}

// Enlazado de las funciones de carga/descarga
module_init(init_modlist_module);
module_exit(exit_modlist_module);
