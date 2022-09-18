#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/ftrace.h>
#include "list.h"

#define BUFFER_LENGTH PAGE_SIZE

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Gestion de lista enlazada de enteros");
MODULE_AUTHOR("Camilo Andres Disidoro - David Manuel Perez Mora");

//TEMPORAL
static char *command;  //Espacio reservado para el comando

//Declaracion de la estructura base
struct list_head mylist; //Cabecera de la lista enlazada
struct list_item { //Estructura representativa de los nodos de la lista
    int data;
    struct list_head links;
};

//Funciones de lectura y escritura del modulo TODO

static ssize_t modlist_read(struct file *filp, char __user *buf, size_t len, loff_t *off) {
  
  int nr_bytes;
  
  if ((*off) > 0) // No hay nada mas pendiente de leer
      return 0;
    
  nr_bytes=strlen(command);
    
  if (len<nr_bytes)
    return -ENOSPC;
  
    // Transfiere informacion del kernel al espacio de usuario
  if (copy_to_user(buf, command,nr_bytes))
    return -EINVAL;
    
  (*off)+=len;  // Actualiza el puntero de fichero
  return nr_bytes; 
}

static ssize_t modlist_write(struct file *filp, const char __user *buf, size_t len, loff_t *off) {
  int available_space = BUFFER_LENGTH-1;
  char action[7];
  int val;
  if ((*off) > 0) // La aplicacion puede escribir en esta entrada solo una vez
    return 0;
  
  if (len > available_space) {
    printk(KERN_INFO "Modlist: not enough space!!\n");
    return -ENOSPC;
  }
  
  // Transifere datos desde espacio usuario a espacio kernel
  if (copy_from_user( &command[0], buf, len ))  
    return -EFAULT;
  sscanf(command, "%s %d", action, &val); //Recoge los parametros que se le ha enviado al modulo
  trace_printk("New value of command: %s\n", command);
  trace_printk("Action tracked: %s\n", action);
  trace_printk("Value tracked, %d\n", val);
  command[len] = '\0'; // Agrega el `\0'
  *off+=len;            // actualiza el puntero de fichero
  
  return len;
}

//Gestion del fichero /proc
static struct proc_dir_entry *proc_entry;

static const struct proc_ops proc_entry_fops = {
    .proc_read = modlist_read,
    .proc_write = modlist_write,    
};

//Carga y Descarga del modulo
int init_modlist_module(void){
    int ret=0;
    INIT_LIST_HEAD(&mylist);
    command = (char *)vmalloc( BUFFER_LENGTH );//TEMP
    if(!command){
        return -ENOMEM;
    }else{
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
    vfree(command);//TEMP
    
    printk(KERN_INFO "Modlist: Module unloaded.\n");
}

//Enlazado de las funciones de carga/descarga
module_init(init_modlist_module);
module_exit(exit_modlist_module);