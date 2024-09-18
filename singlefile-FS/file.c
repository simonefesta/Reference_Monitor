#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/timekeeping.h>
#include <linux/time.h>
#include <linux/buffer_head.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/string.h>

#include <linux/uio.h>
#include "singlefilefs.h"

static struct mutex lock_log; 

ssize_t onefilefs_read(struct file * filp, char __user * buf, size_t len, loff_t * off) {

    loff_t offset;
    struct buffer_head *bh = NULL;
    struct inode * the_inode = filp->f_inode;
    uint64_t file_size = the_inode->i_size;
    int ret;
    int block_to_read;//index of the block to be read from device

    //printk("%s: read operation called with len %ld - and offset %lld (the current file size is %lld)",MOD_NAME, len, *off, file_size);

    //this operation is not synchronized 
    //*off can be changed concurrently 
    //add synchronization if you need it for any reason
    mutex_lock(&lock_log);
    //check that *off is within boundaries
    if (*off >= file_size){
    	 mutex_unlock(&lock_log);
        return 0;
        }
    else if (*off + len > file_size){
        len = file_size - *off;}

    //determine the block level offset for the operation
 
    offset = *off % DEFAULT_BLOCK_SIZE; 
    //just read stuff in a single block - residuals will be managed at the applicatin level
    if (offset + len > DEFAULT_BLOCK_SIZE)
        len = DEFAULT_BLOCK_SIZE - offset;

    //compute the actual index of the the block to be read from device
    block_to_read = *off / DEFAULT_BLOCK_SIZE + 2; //the value 2 accounts for superblock and file-inode on device
    
    //printk("%s: read operation must access block %d of the device",MOD_NAME, block_to_read);

    bh = (struct buffer_head *)sb_bread(filp->f_path.dentry->d_inode->i_sb, block_to_read);
    if(!bh){
    	mutex_unlock(&lock_log);
	return -EIO;
    }
    ret = copy_to_user(buf,bh->b_data + offset, len);
    *off += (len - ret);
    brelse(bh);
    mutex_unlock(&lock_log);
    return len - ret;

}


struct dentry *onefilefs_lookup(struct inode *parent_inode, struct dentry *child_dentry, unsigned int flags) {

    struct onefilefs_inode *FS_specific_inode;
    struct super_block *sb = parent_inode->i_sb;
    struct buffer_head *bh = NULL;
    struct inode *the_inode = NULL;

    //printk("%s: running the lookup inode-function for name %s",MOD_NAME,child_dentry->d_name.name);

    if(!strcmp(child_dentry->d_name.name, UNIQUE_FILE_NAME)){

	
	//get a locked inode from the cache 
        the_inode = iget_locked(sb, 1);
        if (!the_inode)
       		 return ERR_PTR(-ENOMEM);

	//already cached inode - simply return successfully
	if(!(the_inode->i_state & I_NEW)){
		return child_dentry;
	}


	
	//this work is done if the inode was not already cached
	inode_init_owner(current->cred->user_ns, the_inode, NULL, S_IFREG );
	the_inode->i_mode = S_IFREG | S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR | S_IWGRP | S_IXUSR | S_IXGRP | S_IXOTH;
    the_inode->i_fop = &onefilefs_file_operations;
	the_inode->i_op = &onefilefs_inode_ops;

	//just one link for this file
	set_nlink(the_inode,1);

	//now we retrieve the file size via the FS specific inode, putting it into the generic inode
    bh = (struct buffer_head *)sb_bread(sb, SINGLEFILEFS_INODES_BLOCK_NUMBER );
    if(!bh){
		    iput(the_inode);
		    return ERR_PTR(-EIO);
    	}
	FS_specific_inode = (struct onefilefs_inode*)bh->b_data;
	the_inode->i_size = FS_specific_inode->file_size;
    brelse(bh);

    d_add(child_dentry, the_inode);
	dget(child_dentry);

	//unlock the inode to make it usable 
    	unlock_new_inode(the_inode);

	return child_dentry;
    }

    return NULL;

}

/*ref: ssize_t (*write_iter) (struct kiocb *, struct iov_iter *);
- @*kiocb: Kernel IO control Block, usata per op. asincrone IO. Info su dove scrivo.
- @*iter: descrive insieme di buffer di memoria, usata per ottenere
              puntatore al buffer da scrivere e la lunghezza. Info su cosa scrivo.
- @return: byte scritti              
*/
ssize_t onefilefs_write(struct kiocb *kiocb, struct iov_iter *iter){
    
    loff_t off_tostart;
    loff_t offset;
    struct file *filp = kiocb->ki_filp; //estrae ptr alla struttura "file" da kio.
    char *data_to_write= iter->kvec->iov_base; //dati da scrivere
    size_t len = iter->kvec->iov_len; //lunghezza dati da scrivere
 
    int block_to_write; //indice del blocco da scrivere sul dispositivo
   
    struct buffer_head *bh = NULL;          //from read
    struct inode * inode = filp->f_inode;

    mutex_lock(&lock_log);   
    
    off_tostart = i_size_read(inode); //da dove dovrà iniziare la nuova scrittura
	
    //determine the block level offset for the operation

    offset = off_tostart % DEFAULT_BLOCK_SIZE; //offset nel blocco corrente
    //just read stuff in a single block - residuals will be managed at the applicatin level
    if (offset + len > DEFAULT_BLOCK_SIZE) //se eccedo il blocco, mi limito a ciò che posso scrivere
        len = DEFAULT_BLOCK_SIZE - offset;

    //compute the actual index of the the block to be write from device
    block_to_write = off_tostart / DEFAULT_BLOCK_SIZE + 2; //the value 2 accounts for superblock and file-inode on device
    
    /*come nella read, carica il blocco specifico nel buffer*/
    bh = (struct buffer_head *)sb_bread(filp->f_path.dentry->d_inode->i_sb, block_to_write);
    if(!bh){
    	   mutex_unlock(&lock_log);
           printk("ONEFILEFS: Error sb_bread");
	       return -EIO;
    }
    /*scrittura effettiva (a che punto del file scrivo, cosa scrivo, quanto scrivo)*/
    memcpy(bh->b_data +offset, data_to_write, len);

    mark_buffer_dirty(bh); //segnalo che il blocco deve essere riscritto sul disco
    sync_dirty_buffer(bh); //sincronizzo sul disco

    off_tostart += len; //aggiorno l'offset con nuova posizione
    
    inode->i_size = off_tostart;      //new offset
    i_size_write(inode, off_tostart); //aggiorno dimensione in modo sicuro
    brelse(bh);               //rilascio buffer
    mutex_unlock(&lock_log);
    return len;
}

//look up goes in the inode operations
const struct inode_operations onefilefs_inode_ops = {
    .lookup = onefilefs_lookup,
};

const struct file_operations onefilefs_file_operations = {
    .owner = THIS_MODULE,
    .read = onefilefs_read,
    .write_iter = onefilefs_write 
};
