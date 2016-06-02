/*! @file s70357.c
 * IS_Beleg by Markus Klemm
 * */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <openssl/evp.h>

#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>


/*!
 * @param cipher_text Buffer, at least (plain_len + cipher_block_size - 1) bytes big,
 * where the encrypted data will be stored.
 * @param cipher_text_len Actual length of encrypted data in cipher_text in bytes
 */
bool mk_evp_encrypt(const unsigned char *plain_text,
                    const int plain_text_len,
                    unsigned char *cipher_text,
                    int *cipher_text_len,
                    const EVP_CIPHER *cipher,
                    unsigned char *key,
                    unsigned char *iv) {
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    if (!context) {
        return false;
    }
    if (!EVP_EncryptInit_ex(context, cipher, NULL, key, iv)) {
        EVP_CIPHER_CTX_free(context);
        return false;
    }

    *cipher_text_len = 0;
    if (!EVP_EncryptUpdate(context, cipher_text, cipher_text_len, plain_text, plain_text_len)) {
        EVP_CIPHER_CTX_free(context);
        return false;
    }
    if (!EVP_EncryptFinal_ex(context, cipher_text + *cipher_text_len, cipher_text_len)) {
        EVP_CIPHER_CTX_free(context);
        return false;
    }

    EVP_CIPHER_CTX_free(context);
    return true;
}

/*! @param plain_text Buffer that must at least be cipher_text_len + cipher_block_size big
 * */
bool mk_evp_decrypt(const unsigned char *cipher_text,
                    const int cipher_text_len,
                    unsigned char *plain_text,
                    int *plain_text_len,
                    const EVP_CIPHER *cipher,
                    unsigned char *key,
                    unsigned char *iv) {
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    if (!context) {
        return false;
    }
    if (!EVP_DecryptInit_ex(context, cipher, NULL, key, iv)) {
        EVP_CIPHER_CTX_free(context);
        return false;
    }

    *plain_text_len = 0;
    if (!EVP_DecryptUpdate(context, plain_text, plain_text_len, cipher_text, cipher_text_len)) {
        EVP_CIPHER_CTX_free(context);
        return false;
    }
    if (!EVP_DecryptFinal_ex(context, plain_text + *plain_text_len, plain_text_len)) {
        EVP_CIPHER_CTX_free(context);
        return false;
    }

    EVP_CIPHER_CTX_free(context);
    return true;
}

struct file_memory_map_meta {
    int file_desc;
    struct stat file_info;
};

/*! @param digest Must be big engough to hold at least EVP_MAX_MD_SIZE
 * */
bool mk_evp_digest(const unsigned char *text,
                   const size_t text_len,
                   unsigned char *digest,
                   unsigned int *digest_len,
                   const EVP_MD *digest_type) {
    EVP_MD_CTX *context = EVP_MD_CTX_create();
    if (!context) {
        return false;
    }
    if (!EVP_DigestInit_ex(context, digest_type, NULL)) {
        return false;
    }
    if (!EVP_DigestUpdate(context, text, text_len)) {
        return false;
    }
    if (!EVP_DigestFinal_ex(context, digest, digest_len)) {
        return false;
    }

    EVP_MD_CTX_destroy(context);

    return true;
}


void open_file_memory_mapped_read(char *file_path,
                                  void **file_memory,
                                  struct file_memory_map_meta *meta) {
    meta->file_desc = open(file_path, O_RDONLY);
    if (meta->file_desc == -1) {
        fprintf(stderr, "Can't open read file %s", file_path);
        perror(" ");
        exit(EXIT_FAILURE);
    }

    if (stat(file_path, &meta->file_info) != 0) {
        perror("Can't get source file infos");
        exit(EXIT_FAILURE);
    }
    void *source_mem = mmap(NULL, meta->file_info.st_size, PROT_READ, MAP_FILE | MAP_PRIVATE, meta->file_desc, 0);
    if (source_mem == MAP_FAILED) {
        perror("Mapping read file failed");
        exit(EXIT_FAILURE);
    }
    *file_memory = source_mem;
}

void open_file_memory_mapped_write(char *file_path,
                                   void **file_memory,
                                   struct file_memory_map_meta *meta,
                                   size_t size) {
    meta->file_desc = open(file_path, O_TRUNC | O_CREAT | O_RDWR, 744);
    if (meta->file_desc == -1) {
        fprintf(stderr, "Can't open write file %s", file_path);
        perror(" ");
        exit(EXIT_FAILURE);
    }

    if (stat(file_path, &meta->file_info) != 0) {
        perror("Can't get source file infos");
        exit(EXIT_FAILURE);
    }
    void *source_mem = mmap(NULL, size, PROT_WRITE, MAP_FILE | MAP_SHARED, meta->file_desc, 0);
    if (source_mem == MAP_FAILED) {
        perror("Mapping write file failed");
        exit(EXIT_FAILURE);
    }
    *file_memory = source_mem;
}

void close_file_memory_mapped(void **file_memory, struct file_memory_map_meta *meta) {
    munmap(*file_memory, meta->file_info.st_size);
    close(meta->file_desc);
}

void create_key_iv_from_file(char *key_iv_path, unsigned char **key, unsigned char **iv, const EVP_CIPHER *cipher) {
    FILE *f = fopen(key_iv_path, "rb");
    if (!f) {
        fprintf(stderr, "Could not open file %s", key_iv_path);
        perror(" ");
        exit(EXIT_FAILURE);
    }

    *key = malloc(EVP_CIPHER_key_length(cipher));
    if (*key == NULL) {
        perror("Could not alloc for key");
        exit(EXIT_FAILURE);
    }

    if (EVP_CIPHER_iv_length(cipher) != 0) {
        *iv = malloc(EVP_CIPHER_iv_length(cipher));
        if (*iv == NULL) {
            perror("Could not alloc for iv");
            exit(EXIT_FAILURE);
        }
    } else {
        *iv = NULL;
    }
    if (fread(*key, 1, EVP_CIPHER_key_length(cipher), f) != EVP_CIPHER_key_length(cipher)) {
        fprintf(stderr, "Error while reading key\n");
        exit(EXIT_FAILURE);
    }
    if (*iv != NULL) {
        if (fread(*iv, 1, EVP_CIPHER_iv_length(cipher), f) != EVP_CIPHER_iv_length(cipher)) {
            fprintf(stderr, "Error while reading iv\n");
            exit(EXIT_FAILURE);
        }
    }

    fclose(f);
}

unsigned char *permutate_key(unsigned char *key, unsigned corrupt_byte_pos) {
    key[corrupt_byte_pos] = key[corrupt_byte_pos] + 1; //although in DES, we could reduce to half because of parity bit

    return key;
}

bool is_pdf(unsigned char *data) {
    unsigned char pdf_start[] = {"%PDF"};
    unsigned char pdf_end[] = {"%%EOF"};

    return !memcmp(pdf_start, data, sizeof(pdf_start) - 1); //TODO check pdf_end, but cutaway the padding
}

void decrypt_mode(char *cipher_text_path,
                  char *plain_text_path,
                  char *key_iv,
                  unsigned corrupt_byte_pos,
                  char *cipher) {
    OpenSSL_add_all_algorithms();//Needed for older versions to use EVP_get_cipherbyname
    const EVP_CIPHER *evp_cipher = EVP_get_cipherbyname(cipher);
    EVP_cleanup(); //cleanup for OpenSSL_add_all_algorithms
    if (evp_cipher == NULL) {
        fprintf(stderr, "Cipher %s not found\n", cipher);
        exit(EXIT_FAILURE);
    }


    void *cipher_text_mem;
    struct file_memory_map_meta cipher_text_meta;
    open_file_memory_mapped_read(cipher_text_path,
                                 &cipher_text_mem, &cipher_text_meta);

    void *plain_text_mem;
    struct file_memory_map_meta plain_text_meta;
    open_file_memory_mapped_write(plain_text_path,
                                  &plain_text_mem, &plain_text_meta, cipher_text_meta.file_info.st_size);

    if (chmod(plain_text_path, cipher_text_meta.file_info.st_mode) != 0) {
        perror("Can't copy file permissions");
    }
    if (lseek(plain_text_meta.file_desc, cipher_text_meta.file_info.st_size - 1 + EVP_CIPHER_block_size(evp_cipher),
              SEEK_SET) == -1) {
        perror("Can't seek to new end of destination file");
    }
    unsigned char dummy = 0;
    if (write(plain_text_meta.file_desc, &dummy, 1) == -1) {
        perror("Couldn't write dummy byte");
    }

    unsigned char *key;
    unsigned char *iv;
    create_key_iv_from_file(key_iv, &key, &iv, evp_cipher);


    //now lets try the keys
    const unsigned key_len = EVP_CIPHER_key_length(evp_cipher);
    int plain_len = 0;

    bool decrypt_return = mk_evp_decrypt(cipher_text_mem,
                                         cipher_text_meta.file_info.st_size, plain_text_mem, &plain_len, evp_cipher,
                                         key, iv);
    while (!decrypt_return || !is_pdf(plain_text_mem)) {
        plain_len = 0;
        decrypt_return = mk_evp_decrypt(cipher_text_mem,
                                        cipher_text_meta.file_info.st_size, plain_text_mem, &plain_len, evp_cipher,
                                        permutate_key(key, corrupt_byte_pos), iv);
    }


    free(key);
    free(iv);
    close_file_memory_mapped(&plain_text_mem, &plain_text_meta);
    close_file_memory_mapped(&cipher_text_mem, &cipher_text_meta);
}

void hash_mode(char *text_path,
               char *opt_hash_path,
               char *cipher) {
    OpenSSL_add_all_algorithms();//Needed for older versions to use EVP_get_cipherbyname
    const EVP_CIPHER *evp_cipher = EVP_get_cipherbyname(cipher);
    EVP_cleanup(); //cleanup for OpenSSL_add_all_algorithms
    if (evp_cipher == NULL) {
        fprintf(stderr, "Cipher %s not found\n", cipher);
        exit(EXIT_FAILURE);
    }
    void *text_mem;
    struct file_memory_map_meta text_meta;
    open_file_memory_mapped_read(text_path,
                                 &text_mem, &text_meta);

    //TODO

    close_file_memory_mapped(&text_mem, &text_meta);
}

int main(int argc, char *argv[]) {
    enum mode {
        none, decrypt, encrypt, hash
    } mode = none;
    char in_path[512];
    memset(in_path, '\0', sizeof(in_path));
    char out_path[512];
    memset(out_path, '\0', sizeof(out_path));
    char key_path[512];
    memset(key_path, '\0', sizeof(key_path));
    char cipher[512];
    memset(cipher, '\0', sizeof(cipher));
    unsigned corrupt_byte_pos = -1;

    int flag;
    while ((flag = getopt(argc, argv, "deh i:o:c:k:b:")) != -1) {
        switch (flag) {
            case 'e':
                mode = encrypt;
                break;
            case 'd':
                mode = decrypt;
                break;
            case 'h':
                mode = hash;
                break;
            case 'i':
                strncpy(in_path, optarg, sizeof(in_path) - 1);
                break;
            case 'o':
                strncpy(out_path, optarg, sizeof(out_path) - 1);
                break;
            case 'k':
                strncpy(key_path, optarg, sizeof(key_path) - 1);
                break;
            case 'c':
                strncpy(cipher, optarg, sizeof(cipher) - 1);
                break;
            case 'b':
                errno = 0;
                corrupt_byte_pos = strtol(optarg, NULL, 10);
                if (errno != 0) {
                    perror("Could not read byte position, assuming key is ok");
                    corrupt_byte_pos = -1;
                }
                break;
            default:
                printf("Usage %s -<MODE> -<PARAMETERS>\n", argv[0]);
                printf("\t<MODE>:\n");
                printf("\t\t e Encrypt aka Aufgabe 3\n");
                printf("\t\t d Decrypt aka Aufgabe 1\n");
                printf("\t\t h Hash aka Aufgabe 2\n");
                printf("\t<PARAMETERS>: \n");
                printf("\t\t i Input file path\n");
                printf("\t\t o Output file path, optional for hash mode\n");
                printf("\t\t k Key/IV file path, optional for hash mode\n");
                printf("\t\t c EVP Cipher to be used\n");
                printf("\t\t b Corrupt byte position, counted from 0, optional for hash mode\n");
                return EXIT_FAILURE;
                break;
        }
    }

    switch (mode) {
        case decrypt:
            decrypt_mode(in_path, out_path, key_path, corrupt_byte_pos, cipher);
            break;
        case encrypt:
            //TODO
            break;
        case hash:
            hash_mode(in_path, out_path, cipher);
            break;
        case none:
        default:
            fprintf(stderr, "No mode was specified\n");
            exit(EXIT_FAILURE);
            break;
    }

    return EXIT_SUCCESS;
}
