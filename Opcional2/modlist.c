#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/ftrace.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include "list.h"

#define BUFFER_LENGTH PAGE_SIZE

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Gestion de lista enlazada de enteros");
MODULE_AUTHOR("Camilo Andres Disidoro");


static char *kbuf;  // Espacio reservado para el comando
int n_items;
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
            kfree(item);
        }
    }else{
        trace_printk("List is currently empty!\n");
    }
    n_items = 0;
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
                n_items--;
            }
        }
    }else{
        trace_printk("List is currently empty!\n");
    }
}

// Funciones de lectura y escritura del modulo

static ssize_t modlist_read(struct file *filp, char __user *buf, size_t len, loff_t *off) {
    
    int nr_bytes = 0, offset;
    char *out = kbuf;
    struct list_item* item = NULL;
    struct list_head* cur_node = NULL;

    trace_printk("Reading modlist\n");
    trace_printk("Current count of items: %i\n", n_items);

    if ((*off) > 0) {// No hay nada mas pendiente de leer
        return 0;
    }

    list_for_each(cur_node, &mylist) {
        item = list_entry(cur_node, struct list_item, links);
        //seq_printf(filp, "%d\n", item->data);
        trace_printk("Iteration of list_for_each with value %d\n", item->data);
        offset = sprintf(out, "%d\n", item->data);
        nr_bytes += offset;
        out += offset;
    }

    // Transfiere informacion del kernel al espacio de usuario
    if (copy_to_user(buf, kbuf, nr_bytes)) {
        return -EINVAL;
    }
    
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
    if (copy_from_user(&kbuf[0], buf, len)) {
        return -EFAULT;
    }
    kbuf[len] = '\0';
    trace_printk("New value of kbuf: %s\n", kbuf);

    //Se comprueba que accion se ha solicitado
    if(sscanf(kbuf, "add %i", &val) == 1){
        trace_printk("Accessing add to linked list\n");
        trace_printk("Value tracked, %d\n", val);
        item = (struct list_item*)kmalloc(sizeof(struct list_item), GFP_KERNEL);
        item->data = val;
        list_add_tail(&item->links,&mylist);
        n_items++;
    }else if(sscanf(kbuf, "remove %i", &val) == 1){
        trace_printk("Accessing remove to linked list\n");
        trace_printk("Value tracked, %d\n", val);
        remove_item(val);
    }else if(strcmp(kbuf, "cleanup\n") == 0){
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


//Gestion del fichero seq

static int modlist_seq_show(struct seq_file *seqF, void *v){
    loff_t *spos = v;
    seq_printf(seqF, "%lld\n", (long long)*spos);
    return 0;
}

static void *modlist_seq_start(struct seq_file *seqF, loff_t *pos){
    loff_t *spos = kmalloc(sizeof(loff_t), GFP_KERNEL);
    if(!spos){
        return NULL;
    }
    *spos = *pos;
    return spos;
}

static void *modlist_seq_next(struct seq_file *seqF, void *v, loff_t *pos){
    (*pos)++;
    return modlist_seq_start(seqF, pos);
}

static void modlist_seq_stop(struct seq_file *seqF, void *v){
    /*Nada que hacer*/
}

static struct seq_operations seq_fops = {
    .start = modlist_seq_start,
    .next = modlist_seq_next,
    .stop = modlist_seq_stop,
    .show = modlist_seq_show
};

static int modlist_seq_open(struct inode *inode, struct file *filp){
    return seq_open(filp, &seq_fops);
}

// Gestion del fichero /proc
static struct proc_dir_entry *proc_entry;

static const struct proc_ops proc_entry_fops = {
    .proc_read = modlist_read,
    .proc_write = modlist_write,
    .proc_open = modlist_seq_open
};


// Carga y descarga del modulo
int init_modlist_module(void) {
    int ret = 0;
    n_items = 0;
    INIT_LIST_HEAD(&mylist);
    kbuf = (char *)vmalloc(BUFFER_LENGTH);
    if (!kbuf) {
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
    vfree(kbuf);
    list_cleanup();
    printk(KERN_INFO "Modlist: Module unloaded.\n");
}

// Enlazado de las funciones de carga/descarga
module_init(init_modlist_module);
module_exit(exit_modlist_module);