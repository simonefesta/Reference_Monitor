#include <crypto/hash.h>
#define SHA_256 "sha256"
#define SHA256_DIGEST_SIZE 32 //32 byte = 256 bit

static struct shash_desc shash;
/*ref: https://gist.github.com/vkobel/3100cea3625ca765e4153782314bd03d*/

static int calc_hash(struct crypto_shash *alg, const unsigned char *data, unsigned int datalen, unsigned char *digest){
	int ret;
	shash.tfm = alg;
	ret = crypto_shash_digest(&shash, data, datalen, digest);
	return ret;
}
void hash_to_string(const unsigned char *hash, char *output) {
    int i;
    for (i = 0; i < SHA256_DIGEST_SIZE; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[SHA256_DIGEST_SIZE * 2+1] = '\0';
}
static int do_sha256(const unsigned char *data, unsigned char *out_digest, size_t datalen){
	
    struct crypto_shash *alg;
    char *hash_alg_name = SHA_256;
    

	/*Allocate a cipher handle for a message digest. 
	The returned struct crypto_shash is the cipher 
	handle required for any subsequent API invocation
	 for that message digest.*/
    alg = crypto_alloc_shash(hash_alg_name, 0, 0);
 
    if(IS_ERR(alg)){
        pr_info("can't alloc alg %s\n", hash_alg_name);
        return PTR_ERR(alg);
    }
    calc_hash(alg, data, datalen, out_digest);

   
    /*printk(KERN_INFO "HASH(%s, %i): %02x%02x%02x%02x%02x%02x%02x%02x\0\n",
          data, datalen, out_digest[0], out_digest[1], out_digest[2], out_digest[3], out_digest[4], 
          out_digest[5], out_digest[6], out_digest[7]);*/

    crypto_free_shash(alg);
    return 0;
}

void print_hash(const unsigned char *hash) {
    int i;
    for (i = 0; i < SHA256_DIGEST_SIZE; i++) {
        printk("%02x", hash[i]);
    }
    printk("\n");
}
