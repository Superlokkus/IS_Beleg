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

void decrypt_mode(char *cipher_text_path,
                  char *plain_text_path,
                  char *key_iv,
                  unsigned corrupt_byte_pos,
                  char *cipher) {
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
    if (lseek(plain_text_meta.file_desc, cipher_text_meta.file_info.st_size - 1, SEEK_SET) == -1) {
        perror("Can't seek to new end of destination file");
    }
    unsigned char dummy = 0;
    if (write(plain_text_meta.file_desc, &dummy, 1) == -1) {
        perror("Couldn't write dummy byte");
    }


    close_file_memory_mapped(&plain_text_mem, &plain_text_meta);
    close_file_memory_mapped(&cipher_text_mem, &cipher_text_meta);
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
                printf("\t\t o Output file path\n");
                printf("\t\t k Key/IV file path\n");
                printf("\t\t c EVP Cipher to be used\n");
                printf("\t\t b Corrupt byte position, counted from 0\n");
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
            //TODO
            break;
        case none:
        default:
            fprintf(stderr, "No mode was specified\n");
            exit(EXIT_FAILURE);
            break;
    }

    return EXIT_SUCCESS;
}
