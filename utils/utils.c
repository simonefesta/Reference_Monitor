#include <linux/string.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/user_namespace.h>


#define MODNAME "Reference Monitor"
#define RECORD_SIZE 2*sizeof(pid_t)+2*sizeof(uid_t)+MAX_LEN+66


#define MAX_HASH_SIZE 66
#define MAX_LEN 2048
#define MAX_PATHS 128
#define PASS_LEN 20
#define MAX_PARENTS 10
#define MAX_ACTIVE_KRETPROBES 500

#define LINE_SIZE 256

/*Ritorna il minimo tra due lunghezze*/
size_t min_length(size_t a, size_t b) {
    return (a < b) ? a : b;
}


/*Ottiene il percorso del file eseguibile del processo corrente
 see: https://stackoverflow.com/questions/18862057/get-the-absolute-path-of-current-running-program-in-kernel
      https://elixir.bootlin.com/linux/v5.0.21/source/fs/d_path.c#L256
 */

char *get_current_proc_path(void) {

    char *buf;
    char *result;
    struct file *exe_file;
    struct mm_struct *mm;

    buf = kmalloc(MAX_LEN, GFP_KERNEL);   /*allocazione buffer e controllo errori*/
    if (!buf) {
        printk(KERN_ERR "%s: Impossible to allocate space for buf\n", MODNAME);
        return ERR_PTR(-ENOMEM);
    }

    exe_file = NULL;
    result = NULL;

    mm = get_task_mm(current); //ottiene memory descriptor
    if (!mm) {
        printk(KERN_ERR "%s: Failed to get mm_struct\n", MODNAME);
        kfree(buf);
        return ERR_PTR(-ENOENT);
    }

    mmap_read_lock(mm);     //acquisisco lock
    exe_file = mm->exe_file; //accedo al file eseguibile del processo

    if (exe_file) { //incremento contatori al file e al path
        get_file(exe_file);
        path_get(&exe_file->f_path);
    }
    mmap_read_unlock(mm);  //rilascio lock e struttura
    mmput(mm);

    if (exe_file) { //tramite d_path ottengo percorso completo 
        result = d_path(&exe_file->f_path, buf, MAX_LEN); //Callers should use the returned pointer, not the passed in buffer, to use the name.
        if (IS_ERR(result)) {
            printk(KERN_ERR "%s: Error getting path\n", MODNAME);
        }
        path_put(&exe_file->f_path); //rilascio riferimento percorso e file
        fput(exe_file);
    }

    kfree(buf);

    return result;
}

/*legge buflen byte da path, e li memorizza in buf. Ritorna i byte letti*/
ssize_t read_content(char * path, char *buf, size_t buflen) {
    struct file *filp;
    ssize_t ret;
    ret = -EINVAL;
 
    // Apre il file eseguibile in modalità di sola lettura
    filp = filp_open(path, O_RDONLY,0);
    if (IS_ERR(filp)) {
        printk(KERN_ERR "%s: Failed to open executable file\n",MODNAME);
      
        return PTR_ERR(filp);
    }

    ret = kernel_read(filp, buf, buflen,0);
    if (ret < 0) {
        printk(KERN_ERR "%s: Failed to read executable file\n",MODNAME);
    }
    
    // Chiude il file
    filp_close(filp, NULL);
    return ret;
}


/*Restituisce il percorso completo della directory di lavoro corrente del processo*/	
char *get_cwd(void){
	
    struct path abs_path;
    char *buf;
    char *full_path;
    //printk("%s:  get_cwd called",MODNAME);

    // Alloca il buffer per memorizzare il percorso
    buf = kmalloc(MAX_LEN, GFP_KERNEL);
    if (buf == NULL) {
        printk(KERN_ERR "%s: Failed to allocate memory for path buffer\n", MODNAME);
        return NULL;
    }

    // Ottiene il percorso della directory di lavoro corrente
    get_fs_pwd(current->fs, &abs_path);

    // Converte il percorso in una stringa usando d_path
    full_path = d_path(&abs_path, buf, MAX_LEN);
    if (IS_ERR(full_path)) {
        // Se d_path restituisce un errore, libera il buffer e restituisci NULL
        kfree(buf);
        printk(KERN_ERR "%s: Error getting current working directory\n", MODNAME);
        return NULL;
    }

    // Libera il buffer, poiché d_path ha restituito un puntatore a questo buffer
    return full_path;
}

/*Ritorna vero se il file è un file temporaneo*/
bool is_temp_file(const char *str) {
    size_t len;
    len = strlen(str);

    // Verifica se la lunghezza è sufficiente e se termina con '~'
    if (len > 0 && str[len - 1] == '~') {
        return true;
    }

    // Verifica se la lunghezza è sufficiente e se termina con '.pws'
    if (len > 4 && str[len - 1] == 's' && str[len - 2] == 'w' && str[len - 3] == 'p' && str[len - 4] == '.') {
        return true;
    }

    // Verifica se la lunghezza è sufficiente e se termina con '.xpws'
    if (len > 5 && str[len - 1] == 's' && str[len - 2] == 'w' && str[len - 3] == 'p' && str[len - 4] == 'x' && str[len - 6] == '.') {
        return true;
    }

    return false;
}

/*Ottiene il percorso assoluto di un file.*/

char *get_absolute_path_by_name(char *name) {

	struct path path;
    char *result;
    char *abs_path;
    int err;
    result = NULL;

    // Ottieni la struttura path dal nome del file
    err = kern_path(name, LOOKUP_FOLLOW, &path);
    if (err<0) {
        //printk(KERN_ERR "%s: Error in kern_path: %d\n", MODNAME, err);
        return NULL;
    }

    // Alloca spazio per il percorso assoluto
    result = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!result) {
        printk(KERN_ERR "%s: Error allocating memory for result\n", MODNAME);
        return NULL;
    }

    // Ottieni il percorso assoluto utilizzando d_path()
    abs_path = d_path(&path, result, PATH_MAX);
    if (IS_ERR(abs_path)) {
        printk(KERN_ERR "%s: Error in d_path: %ld\n", MODNAME, PTR_ERR(abs_path));
        kfree(result);
        return NULL;
    }

    return abs_path;
}

/*Ottiene, dato un path, il percorso padre*/
char *get_dir_parent(char *path) {
    static char parent[PATH_MAX];
    int len;
    int i;
    len = strlen(path);

    // Copia il percorso originale in parent
    strncpy(parent, path, PATH_MAX);
    // Cerca l'ultimo slash nel percorso
    for (i= len - 1; i >= 0; i--) {
        if (parent[i] == '/') {
            // Termina la stringa dopo l'ultimo slash per ottenere la directory padre
            parent[i] = '\0';
            break;
        }
    }
    return parent;
}
