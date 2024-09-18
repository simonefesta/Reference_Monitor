#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/scatterlist.h>
#include <linux/fs_struct.h>
#include <linux/mm_types.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/cdev.h>
#include <linux/errno.h>
#include <linux/device.h>
#include <linux/stat.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/interrupt.h>
#include <linux/time.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <asm/page.h>
#include <asm/cacheflush.h>
#include <asm/apic.h>
#include <linux/syscalls.h> 
#include <linux/list.h>
#include <linux/uaccess.h>
#include <linux/spinlock.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/slab.h>
#include "utils/utils.c"
#include "crypto/hashdef.c"

#define target_func0 "do_filp_open"
#define target_func1 "do_mkdirat"
#define target_func2 "do_rmdir"
#define target_func3 "do_unlinkat"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Simone Festa");
MODULE_DESCRIPTION("Reference Monitor Implementation");

static char *the_file = NULL;
module_param(the_file, charp, 0660);
MODULE_PARM_DESC(the_file, "Path to the file");

#define DEVICE_NAME "/dev/reference_monitor"  /* Device file name in /dev/ */

#define BUFFER_SIZE (16 * 1024) // 16 KB
#define HASH_SIZE 33

static ssize_t rm_write_commands(struct file *, const char *, size_t, loff_t *);

static int Major;            /* Major number assigned to reference monitor device driver */

static char *the_file;



typedef enum reference_monitor_state{
	ON,
	OFF,
	REC_ON,
	REC_OFF,
}ref_monitor_state;

// Mappa dei nomi degli stati
static const char *state_names[] = {
    [ON] = "ON",
    [OFF] = "OFF",
    [REC_ON] = "REC_ON",
    [REC_OFF] = "REC_OFF"
};

static const char *get_state_name(ref_monitor_state state) {
    return (state >= 0 && state < sizeof(state_names) / sizeof(state_names[0])) ? state_names[state] : "UNKNOWN";
}

struct my_kretprobe_data {
    int block_flag; // Flag per indicare se l'operazione deve essere bloccata
};


typedef struct reference_monitor_info{
	ref_monitor_state state;
	char password[33]; 
	char blacklist[MAX_PATHS][MAX_LEN];
	int last_pos;						//last position in blacklist
	
}RM_info;

RM_info RM;
static spinlock_t RM_lock;

bool verify_password(char *input_password){

    int result_code; //val di ritorno funzione hashing
    bool is_match;
    unsigned char *computed_hash; //contiene hash calcolato
    unsigned char stored_hash[HASH_SIZE]; //array che contiene l'hash della password memorizzata.

    // Alloca memoria per l'hash calcolato
    computed_hash = kmalloc(HASH_SIZE, GFP_KERNEL);
    if (!computed_hash) {
        printk(KERN_ERR "%s: Failed to allocate memory for password hash",MODNAME);
        return false;
    }

    // Inizializza l'array dell'hash calcolato
    memset(computed_hash, 0, HASH_SIZE);

    // Calcola l'hash SHA-256 della password di input
    result_code = do_sha256(input_password, computed_hash, strlen(input_password));
    if (result_code != 0) {
        printk(KERN_ERR "%s:Error computing SHA-256 hash for the input password",MODNAME);
        kfree(computed_hash);
        return false;
    }

    // Blocca l'accesso alla variabile condivisa
    spin_lock(&RM_lock);

    // Copia l'hash della password memorizzata
    strncpy(stored_hash, RM.password, HASH_SIZE);

    // Sblocca l'accesso alla variabile condivisa
    spin_unlock(&RM_lock);

    // Confronta l'hash calcolato con l'hash memorizzato
    if (strncmp(computed_hash, stored_hash, min_length(strlen(computed_hash), strlen(stored_hash))) == 0) {
        is_match = true;
    } else {
        is_match = false;
    }

    // Libera la memoria allocata
    kfree(computed_hash);

    // Restituisce il risultato del confronto
    return is_match;

}
	
int rm_new_pass(const char *new_pass) {
    // Verifica della lunghezza della password
    if (!new_pass || strlen(new_pass) > PASS_LEN - 1) {
        printk(KERN_ERR "%s: Empty or too long password!\n",MODNAME);
        return -EINVAL; // Restituisce un codice di errore standard
    }

    // Blocco della sezione critica
    spin_lock(&RM_lock);

    // Crittografia della password
    do_sha256(new_pass, RM.password, strlen(new_pass));
	printk(KERN_INFO "%s: Password Updated successfully!\n",MODNAME);

    // Sblocco della sezione critica
    spin_unlock(&RM_lock);

    return 0;
}

/*kernelLevelTaskManagement/workqueues.c*/

struct tuple_data{
	pid_t tgid;	//group identifier
	pid_t pid;	//thread identifier
	uid_t user_id;
	uid_t effective_id; 
	char program_path[MAX_LEN];
	char content_hash[MAX_HASH_SIZE];
	
};

typedef struct {
    struct tuple_data log_info;
	struct work_struct the_work;
} packed_work_deferred;

//Formatta i dati da "data" verso "buffer", avente size "buffer_size"
bool format_record_to_buffer(packed_work_deferred *data, char *buffer, size_t buffer_size) {
    int written;

    // Formatta ogni campo della struttura record come stringa e concatenali nel buffer
    written = snprintf(buffer, buffer_size, "TGID: %d | PID: %d | UID: %d | EUID: %d | Program Path: %s | Program hashed content: %s \n",
                       data->log_info.tgid, 
					   data->log_info.pid, 
					   data->log_info.user_id, 
					   data->log_info.effective_id,
                       data->log_info.program_path, 
					   data->log_info.content_hash);

    // Verifica se l'intero messaggio è stato scritto nel buffer
    if (written < 0 || written >= buffer_size) {
        // Se written < 0, c'è stato un errore. Se written >= buffer_size, il buffer era troppo piccolo.
        return false;
    }

    return true;
}

bool append_to_the_file(char* line) {
    loff_t pos = 0;            // Posizione iniziale, non usata per O_APPEND
    int ret;                   // Numero di byte scritti o codice di errore
    struct file *file;

    // Apri il file in modalità scrittura con append
    file = filp_open(the_file, O_WRONLY | O_APPEND, 0);
    if (IS_ERR(file)) {
        printk(KERN_ERR "%s: Failed to open the_file\n", MODNAME);
        return false;
    }

    // Scrivi la stringa nel file
    ret = kernel_write(file, line, strlen(line), &pos);
    if (ret < 0) {
        printk(KERN_ERR "%s: Failed to write to file\n", MODNAME);
        filp_close(file, NULL);
        return false;
    }

    // Verifica se la scrittura è stata parziale
    if (ret < strlen(line)) {
        printk(KERN_INFO "%s: Wrote only %d bytes, retrying...\n", MODNAME, ret);
        kernel_write(file, line + ret, strlen(line) - ret, &pos);
    }

    // Stampa un messaggio di conferma
    printk(KERN_INFO "%s: File \"the_file\" written with line: %s\n", MODNAME, line);

    // Chiudi il file
    filp_close(file, NULL);

    return true;
}

void do_deferred_work(struct work_struct *work) {

	loff_t offset;
	int i;
	ssize_t bytes_read;
	int ret;
	struct file *filp;

	unsigned char *prev_hash = NULL;  // Hash accumulato dei blocchi precedenti
	unsigned char *curr_hash = NULL;  // Hash corrente del blocco
	unsigned char *buffer = NULL;     // Buffer per leggere i blocchi del file
	char *line = NULL;                // Buffer per scrivere i dati di log

	
	packed_work_deferred *data = container_of(work, packed_work_deferred, the_work);

	// Alloca memoria per l'hash precedente
	prev_hash = kzalloc(HASH_SIZE, GFP_KERNEL);
	if (!prev_hash) {
    	printk(KERN_ERR "%s: Failed to allocate memory for prev_hash\n", MODNAME);
    	return;
	}

	// Alloca memoria per l'hash corrente
	curr_hash = kzalloc(HASH_SIZE, GFP_KERNEL);
	if (!curr_hash) {
    	printk(KERN_ERR "%s: Failed to allocate memory for curr_hash\n", MODNAME);
    	goto free_prev_hash;
	}

	// Alloca il buffer per la lettura dei blocchi
	buffer = kzalloc(BUFFER_SIZE, GFP_KERNEL);
	if (!buffer) {
    	printk(KERN_ERR "%s: Failed to allocate memory for buffer\n", MODNAME);
    	goto free_curr_hash;
	}

	// Alloca il buffer per il formato del record di log
	line = kzalloc(RECORD_SIZE, GFP_KERNEL);
	if (!line) {
    	printk(KERN_ERR "%s: Failed to allocate memory for line\n", MODNAME);
    	goto free_buffer;
	}

	// Apri il file eseguibile in modalità di sola lettura
	filp = filp_open(data->log_info.program_path, O_RDONLY, 0);
	if (IS_ERR(filp)) {
    	printk(KERN_ERR "%s: Failed to open file %s\n", MODNAME, data->log_info.program_path);
    	goto free_line;
	}

	// Leggi i dati dal file blocco per blocco, calcolo di sha256
	offset = 0;
	while ((bytes_read = kernel_read(filp, buffer, BLOCK_SIZE, &offset)) > 0) {
    	// Calcola l'hash del blocco corrente
    	ret = do_sha256(buffer, curr_hash, bytes_read);
    	if (ret < 0) {
        	printk(KERN_ERR "%s: Failed to calculate hash for block\n", MODNAME);
        	goto close_file;
    	}

    	// Fai lo XOR tra l'hash del blocco corrente e l'hash accumulato
    	for (i = 0; i < HASH_SIZE; i++) {
        	prev_hash[i] ^= curr_hash[i];
    	}
	}

	// Chiudi il file una volta completata la lettura
	filp_close(filp, NULL);

	// Converti l'hash finale in una stringa
	hash_to_string(prev_hash, data->log_info.content_hash);

	// Scrivi il record di log formattato
	if (format_record_to_buffer(data, line, RECORD_SIZE)) {
    	if (!append_to_the_file(line)) {
        printk(KERN_ERR "%s: Failed to append to the file!\n", MODNAME);
    	}
	}

	// Libera la memoria allocata e termina correttamente
	kfree(prev_hash);
	kfree(curr_hash);
	kfree(buffer);
	kfree(line);
	return;

	// Gestione degli errori: libera la memoria allocata in ordine inverso
close_file:
    filp_close(filp, NULL);
free_line:
    kfree(line);
free_buffer:
    kfree(buffer);
free_curr_hash:
    kfree(curr_hash);
free_prev_hash:
    kfree(prev_hash);

}

void schedule_deferred_work(void) {
   
    packed_work_deferred *the_task;
	struct cred *current_credentials;
	char *process_path;

    // Alloca memoria per i dati del task differito
    the_task = kzalloc(sizeof(packed_work_deferred), GFP_KERNEL);
    if (!the_task) {
        printk(KERN_ERR "%s: Failed to allocate memory for deferred task\n", MODNAME);
        return;
    }

    // Ottieni le credenziali del processo corrente
    current_credentials = (struct cred *)get_task_cred(current);

    // Popola la struttura con i dati del processo corrente
    the_task->log_info.tgid = current->tgid;
    the_task->log_info.pid = current->pid;
    the_task->log_info.user_id = current_credentials->uid.val;
    the_task->log_info.effective_id = current_credentials->euid.val;
    
    // Ottieni il percorso del file eseguibile del processo corrente
    process_path = get_current_proc_path();
    if (IS_ERR(process_path)) {
        printk(KERN_ERR "%s: Failed to retrieve process path\n", MODNAME);
        kfree(the_task); // Libera la memoria allocata per i dati
        return;
    }

    // Copia il percorso nel campo program_path della struttura log_info
    strncpy(the_task->log_info.program_path, process_path, MAX_LEN);

    // Stampa le informazioni raccolte
    printk("schedule_deferred_task: pid %d, tgid %d, uid %d, euid %d, path %s\n",
           the_task->log_info.pid, 
		   the_task->log_info.tgid,
           the_task->log_info.user_id, 
		   the_task->log_info.effective_id,
           the_task->log_info.program_path);

    // Inizializza il lavoro differito con la funzione di callback appropriata
    __INIT_WORK(&(the_task->the_work), do_deferred_work,(unsigned long)(&(the_task->the_work)));

    // Accoda il lavoro alla coda di lavoro
    schedule_work(&the_task->the_work);

}
/* AGGIUNTA E RIMOZIONE PATH */

static bool is_reconfigurable(void) {
    if (RM.state == ON || RM.state == OFF) {
        printk(KERN_ERR "%s: Reference Monitor is not reconfigurable\n", MODNAME);
        return false;
    }
    return true;
}

static int find_path_in_blacklist(const char *path) {
    int i;
    for (i = 0; i <= RM.last_pos; i++) {
        if (strcmp(RM.blacklist[i], path) == 0) {
            return i; // Ritorna l'indice se trovato
        }
    }
    return -1; // Ritorna -1 se non trovato
}

int rm_add_path(char *new_path){
	char *abs_path;

	spin_lock(&RM_lock);
	if (!is_reconfigurable()){
							spin_unlock(&RM_lock);
							return -EINVAL;
						   }
	
	
    abs_path = get_absolute_path_by_name(new_path);
    if(abs_path == NULL){
    		printk(KERN_ERR "%s: Path/file doesn't exist\n",MODNAME);
    		spin_unlock(&RM_lock);
    		return -EINVAL;
    	}
	
    // Verifica se il percorso è già presente nella blacklist
    if (find_path_in_blacklist(abs_path) != -1) {
    	printk(KERN_ERR "%s: Path/file already exists.\n",MODNAME);
        spin_unlock(&RM_lock);
        return -EEXIST;
    }
	// Controllo lunghezza path
	if(strlen(abs_path)+1> MAX_LEN){
		printk(KERN_ERR "Path is too long\n"); 
		spin_unlock(&RM_lock); 
		return -ENAMETOOLONG;
	}
	// Aggiungi il percorso alla blacklist

	strncpy(RM.blacklist[++RM.last_pos], abs_path, strlen(abs_path) + 1);
	printk(KERN_INFO "%s: Path/file added into blacklist\n", MODNAME);

	spin_unlock(&RM_lock);
	return 0;
		
}

int rm_delete_path(char * path){
	char *abs_path;
	int i;

	spin_lock(&RM_lock);
	if (!is_reconfigurable()){
							spin_unlock(&RM_lock);
							return -EINVAL;
						   }
	
	abs_path = get_absolute_path_by_name(path);
	if(abs_path == NULL){
    		printk(KERN_ERR "%s: Path/file doesn't exist\n",MODNAME);
    		spin_unlock(&RM_lock);
    		return -EINVAL;
    	}

	for(i=0; i<=RM.last_pos; i++){
		if(strcmp(RM.blacklist[i], abs_path)==0){
			if (i != RM.last_pos) {
            	// Sposta l'ultimo elemento nella posizione da rimuovere
            	memmove(RM.blacklist[i], RM.blacklist[RM.last_pos], MAX_LEN);
        	}

        	// Azzeramento dell'ultimo elemento (se non è già stato azzerato)
        	memset(RM.blacklist[RM.last_pos], 0, MAX_LEN);
        
        	// Decrementa la posizione dell'ultimo elemento
        	RM.last_pos--;
			printk(KERN_INFO "%s: Path/file removed from blacklist\n", MODNAME);

        	spin_unlock(&RM_lock);
			return 0;
		}
	}
	printk(KERN_ERR "%s: Path/file not found in blacklist\n", MODNAME);
	spin_unlock(&RM_lock);
	return 0;
}

int checkBlacklist(char* open_path){
	int i;
	//checking blacklist
	if (open_path == NULL){
			return -1;
	}
	for(i=0; i<=RM.last_pos; i++){
		if(strcmp(RM.blacklist[i], open_path)==0){
			
			return -EPERM;
		}
	}

	return 0;
}

static int post_handler(struct kretprobe_instance *kp, struct pt_regs *regs){
	struct my_kretprobe_data *data;
	data = (struct my_kretprobe_data *)kp->data;

	if (data->block_flag) {
        // Imposta il codice di errore per bloccare l'operazione
        regs->ax = -EACCES;
        data->block_flag = 0; // Reset del flag
        printk(KERN_INFO "%s: Operation blocked by kretprobe\n",MODNAME);
    }


	return 0;
}

static int do_mkdirat_wrapper(struct kretprobe_instance *kp, struct pt_regs *regs){
	char *name;
    char *abs_path;
	char *directory;
	char *parent_path;

	struct my_kretprobe_data *data;
	data  = (struct my_kretprobe_data *)kp->data;

    // Ottieni il nome del file dal secondo parametro della syscall
    name = (char *) ((struct filename *)(regs->si))->name;

    if (IS_ERR(name)) {
        pr_err(KERN_ERR "%s: Error in get filename\n",MODNAME);
        return 0;
    }

    // Se il file è un file temporaneo, non fare nulla
    if (is_temp_file(name)) {
        return 0;
    }

    // Ottieni il percorso assoluto
    abs_path = get_absolute_path_by_name(name);
	if (abs_path == NULL){}

				// Recupera il percorso della directory genitore del file
            	parent_path = get_dir_parent(name);

            	// Recupera il percorso assoluto della directory genitore
            	abs_path = get_absolute_path_by_name(parent_path);

            	// Usa il percorso assoluto della directory genitore se è valido
            	if (abs_path == NULL) {
                	// Se il percorso assoluto non è valido, usa la directory corrente come fallback
               		directory = get_cwd();
				} else {
						directory = abs_path;
				}

	
    // Controlla la blacklist
    

	spin_lock(&RM_lock);
    while (directory != NULL && strcmp(directory, "") != 0 && strcmp(directory, " ") != 0) {
        if (checkBlacklist(directory) == -EPERM) {
			
			data->block_flag = 1; // Imposta il flag per bloccare l'operazione

            printk(KERN_ERR "%s: path or its parent directory is in blacklist: %s\n",MODNAME, directory);
			schedule_deferred_work();
            // Blocca l'operazione impostando il codice di errore nel registro di ritorno
			regs->ax = -EPERM;
			regs->di = (unsigned long)NULL;


            printk(KERN_ERR "%s: mkdirat operation was blocked: %s\n",MODNAME, name);
			spin_unlock(&RM_lock);
            return 0;
        }

        // Ottieni la directory genitore
        directory = get_dir_parent(directory);
    }
	spin_unlock(&RM_lock);
    return 0;
}



static int do_rmdir_wrapper(struct kretprobe_instance *kp, struct pt_regs *regs) {

    char *name;
    char *abs_path;
	char *directory;
	struct my_kretprobe_data *data;
	data  = (struct my_kretprobe_data *)kp->data;
    // Ottieni il nome del file dal secondo parametro della syscall
    name = (char *)((struct filename *)(regs->si))->name;

    if (IS_ERR(name)) {
        pr_err(KERN_ERR "%s: Error in get filename\n",MODNAME);
        return 0;
    }

    // Se il file è un file temporaneo, non fare nulla
    if (is_temp_file(name)) {
        return 0;
    }

    // Ottieni il percorso assoluto
    abs_path = get_absolute_path_by_name(name);
    if (!abs_path) {
        return 0;
    }

    // Controlla la blacklist
    directory = abs_path;
	spin_lock(&RM_lock);
    while (directory != NULL && strcmp(directory, "") != 0 && strcmp(directory, " ") != 0) {

        if (checkBlacklist(directory) == -EPERM) {
			data->block_flag = 1; // Imposta il flag per bloccare l'operazione

            printk(KERN_ERR "%s: path or its parent directory is in blacklist: %s\n",MODNAME, directory);
			schedule_deferred_work();
            // Blocca l'operazione impostando il codice di errore nel registro di ritorno
			regs->ax = -EPERM;
			regs->di = (unsigned long)NULL;


            printk(KERN_ERR "%s: rmdir/unlinkat operation was blocked: %s\n",MODNAME, name);
			spin_unlock(&RM_lock);
            return 0;
        }

        // Ottieni la directory genitore
        directory = get_dir_parent(directory);
    }
	spin_unlock(&RM_lock);
    return 0;
}


struct open_flags {
	int open_flag;
	umode_t mode;
	int acc_mode;
	int intent;
	int lookup_flags;
};

/* struct file *do_filp_open(int dfd, struct filename *pathname,
		const struct open_flags *op)
		
Nb: con regs associamo ai parametri della funzione associata: ri (dfd), si (pathname), dx (flags)..)		
*/
static int do_filp_open_wrapper(struct kretprobe_instance *kp, struct pt_regs *regs){
	
	struct open_flags *flags; 
	const char *name;
	int dfd;
	int open_flag;  //è il campo "int open_flag" della struct "Open_flags" della do_filp_open
	char *abs_path;
	char *directory;
	char *parent_path;
	struct my_kretprobe_data *data;
	data  = (struct my_kretprobe_data *)kp->data;
		
	/*otteniamo le informazioni utili da "regs"*/

	dfd = regs->di;  //first argument
	name = ((struct filename *)(regs->si))->name; //second argument
	if (IS_ERR(name)) {
			pr_err(KERN_ERR "%s: Error getting filename\n",MODNAME);
			return 0;
	}
		
	flags = (struct open_flags *)(regs->dx); //third argument
	open_flag = flags->open_flag;
		
	//se il file è aperto in lettura, ritorno 
		
	if(!(open_flag & O_RDWR) && !(open_flag & O_WRONLY) && !(open_flag & (O_CREAT | __O_TMPFILE | O_EXCL )))  return 0;
	
	abs_path = get_absolute_path_by_name((char *) name); //prendo l'absolute path

	if (open_flag & O_CREAT) {
        	if (abs_path == NULL) { /*se sto creando un file (quindi abs_path nullo) */
            	// Recupera il percorso della directory genitore del file
            	parent_path = get_dir_parent((char *)name);

            	// Recupera il percorso assoluto della directory genitore
            	abs_path = get_absolute_path_by_name(parent_path);

            	// Usa il percorso assoluto della directory genitore se è valido
            	if (abs_path == NULL) {
                	// Se il percorso assoluto non è valido, usa la directory corrente come fallback
               		directory = get_cwd();
            	} else {
                	directory = abs_path;
            	}
      	  } else {
            directory = abs_path;
        }
    //} else if (open_flag & (O_RDWR | O_WRONLY | O_TRUNC)) {
	} else {
        // Se non è necessaria la creazione, ma è necessaria la lettura/scrittura
        if (abs_path != NULL) {
            directory = abs_path;
        }
    }

	spin_lock(&RM_lock);
	
	/*controllo della blacklist*/
	while (directory && *directory && strcmp(directory, " ") != 0){ //controllo che sia non NULL e non vuoto.
        		
		if (checkBlacklist(directory) == -EPERM ) {
				data->block_flag = 1; // Imposta il flag per bloccare l'operazione
			    printk(KERN_ERR "%s: Error: path or its parent directory is in blacklist: %s\n",MODNAME, directory);
		        schedule_deferred_work(); //log dell'evento
			    flags->open_flag = O_RDONLY;
				spin_unlock(&RM_lock);
			    return 0;
		}
		directory = get_dir_parent(directory); //mi permette di iterare sui parent della directory passata (es: /home/user -> /home/)
	}
	spin_unlock(&RM_lock);
	return 0;
}



static int rm_open(struct inode *inode, struct file *file) {
//device opened by a default nop
   return 0;
}


//struct file operations containing mapping between actual driver's operations and standard operations
static struct file_operations fops = {
  .owner = THIS_MODULE,	
  .write = rm_write_commands,
  .open  = rm_open,
};


static struct kretprobe kp_open = {
    .kp.symbol_name = target_func0,
	.data_size = sizeof(struct my_kretprobe_data), // Dimensione dei dati
    .entry_handler=do_filp_open_wrapper,
    .handler=post_handler
};


static struct kretprobe kp_mkdir = {
    .kp.symbol_name = target_func1,
	.data_size = sizeof(struct my_kretprobe_data), // Dimensione dei dati
    .entry_handler=do_mkdirat_wrapper,
    .handler=post_handler
};

static struct kretprobe kp_rmdir = {
    .kp.symbol_name = target_func2,
	.data_size = sizeof(struct my_kretprobe_data), // Dimensione dei dati
    .entry_handler=do_rmdir_wrapper,
    .handler=post_handler
};

static struct kretprobe kp_unlink = {
    .kp.symbol_name = target_func3,
    .data_size = sizeof(struct my_kretprobe_data), // Dimensione dei dati
    .entry_handler=do_rmdir_wrapper,
    .handler=post_handler
};


void rm_update_state(enum reference_monitor_state new_state){

	const char *old_state_name;
	spin_lock(&RM_lock);
	old_state_name = get_state_name(RM.state);
	
	if((RM.state == OFF || RM.state == REC_OFF) && (new_state == REC_ON || new_state == ON )){

		enable_kretprobe(&kp_open);
	 	enable_kretprobe(&kp_unlink);
		enable_kretprobe(&kp_mkdir);
	 	enable_kretprobe(&kp_rmdir);		
	
	}
	else if((RM.state == ON || RM.state == REC_ON) && (new_state == REC_OFF || new_state == OFF)){
		
		disable_kretprobe(&kp_open);
		disable_kretprobe(&kp_unlink);
		disable_kretprobe(&kp_rmdir);
		disable_kretprobe(&kp_mkdir);

		
	}
    RM.state = new_state;
    printk("%s: state changed from %s to %s\n", MODNAME, old_state_name, get_state_name(RM.state));

	spin_unlock(&RM_lock);
	
}

static ssize_t rm_write_commands(struct file *f, const char *buff, size_t len, loff_t *off){
	
	int j,ret;
	char* args[3];
	char *token;
	char *buffer = kmalloc(LINE_SIZE, GFP_KERNEL);

	ret = 0;
	j = 0;

	if (len >= LINE_SIZE) {
        printk(KERN_ERR "%s: Input length too large\n", MODNAME);
        return -EINVAL;
    }
	
	if (!buffer) {
	    printk(KERN_ERR "%s: Unable to allocate memory for buffer in rm_write_commands\n",MODNAME);
	    return -ENOMEM;
	}
	
  	ret = copy_from_user(buffer,buff,len);

	//separo gli argomenti passati dall'utente
  	token = strsep(&buffer, " ");
	while (token != NULL && j < 3) {
	    args[j++] = token;
	    token = strsep(&buffer, " ");
	}
  	
	kfree(buffer);
  	if(verify_password(args[2])){	
		if(strcmp(args[0],"state")==0){

			if(strcmp(args[1],"ON")==0){

					rm_update_state(ON);
			} 
			else if(strcmp(args[1],"OFF")==0){

					rm_update_state(OFF);
			}
			else if(strcmp(args[1],"REC_ON")==0){
					
					rm_update_state(REC_ON);
			}
			else if(strcmp(args[1],"REC_OFF")==0){
				
					rm_update_state(REC_OFF);
			}
				else{
				
				printk(KERN_ERR "%s: Invalid argument\n",MODNAME);
			}
		}
		else if(strcmp(args[0],"newpass")==0){
			
			rm_new_pass(args[1]);
		}
		else if (strcmp(args[0],"addpath")==0){
			
			rm_add_path(args[1]);
		}
		else if(strcmp(args[0],"deletepath")==0){
		
			rm_delete_path(args[1]);
		}else{
		
			 printk(KERN_ERR " %s: Invalid argument",MODNAME);
			}
		
		return len;
	
	}
	printk(KERN_ERR "%s: Wrong password passed: %s\n",MODNAME, args[2]);

	return -1;
}



/*ref: VFS/broadcast.c, baseline-char-dev*/
int init_module(void) {

	int ret;
		
	//registration of the RM as a char device driver
	Major = register_chrdev(0, DEVICE_NAME, &fops);

	if (Major < 0) {
		printk ("Registering the character device failed with %d\n", Major);
		return Major;
	}
	
	printk(KERN_INFO "%s: RM device registered, it is assigned major number %d. The default password is 'default'.\n",MODNAME, Major);
	
	do_sha256("default", RM.password, strlen("default"));
	
	
	ret = register_kretprobe(&kp_open);
	if (ret < 0) {
                printk(KERN_ERR "%s: kprobe filp open registering failed, returned %d\n",MODNAME,ret);
                return ret;
        }
    ret = register_kretprobe(&kp_unlink);
    if (ret < 0) {
                printk(KERN_ERR "%s: kprobe unlinkat registering failed, returned %d\n",MODNAME,ret);
                return ret;
        } 
    
	ret = register_kretprobe(&kp_mkdir);
    if (ret < 0) {
                printk(KERN_ERR "%s: kprobe mkdir registering failed, returned %d\n",MODNAME,ret);
                return ret;
        }
	ret = register_kretprobe(&kp_rmdir);
    if (ret < 0) {
                printk(KERN_ERR "%s: kprobe rmdir registering failed, returned %d\n",MODNAME,ret);
                return ret;
        }
    
    rm_update_state(REC_ON);
        
	return 0;
}


void cleanup_module(void) {
	printk("%s: shutting down\n",MODNAME);
	rm_update_state(OFF);

	//unregistering kprobes


	unregister_kretprobe(&kp_open);
	unregister_kretprobe(&kp_unlink);
	unregister_kretprobe(&kp_mkdir);

	unregister_kretprobe(&kp_rmdir);

	printk("%s: kprobes unregistered\n", MODNAME);
	unregister_chrdev(Major, DEVICE_NAME);
	printk(KERN_INFO "%s: device unregistered, it was assigned major number %d\n",DEVICE_NAME,Major);
	
}



