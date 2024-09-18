#ifndef _MY_CRYPTO__
#define _MY_CRYPTO__
int calc_hash(struct crypto_shash *alg, const unsigned char *data, unsigned int datalen, unsigned char *digest);
void hash_to_string(const unsigned char *hash, char *output) ;
int do_sha256(const unsigned char *data, unsigned char *out_digest, size_t datalen);


void print_hash(const unsigned char *hash) ;
#endif
