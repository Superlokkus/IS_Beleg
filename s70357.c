/*! @file s70357.c
 * IS_Beleg by Markus Klemm
 * */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <openssl/evp.h>

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

void open_source_file_memory_mapped(char *file_path,
                                    void **file_memory,
                                    struct file_memory_map_meta *meta) {
    meta->file_desc = open(file_path, O_RDONLY);
    if (meta->file_desc == -1) {
        perror("Can't open source file");
        exit(EXIT_FAILURE);
    }

    if (stat(file_path, &meta->file_info) != 0) {
        perror("Can't get source file infos");
        exit(EXIT_FAILURE);
    }
    void *source_mem = mmap(NULL, meta->file_info.st_size, PROT_READ, MAP_FILE | MAP_PRIVATE, meta->file_desc, 0);
    if (source_mem == MAP_FAILED) {
        perror("Mapping source file failed");
        exit(EXIT_FAILURE);
    }
    *file_memory = source_mem;
}

void close_source_file_memory_mapped(void **file_memory, struct file_memory_map_meta *meta) {
    munmap(*file_memory, meta->file_info.st_size);
    close(meta->file_desc);
}

void decrypt(char *cipher_text_path,
             char *plain_text_path,
             char *key_iv,
             int corrupt_byte_pos,
             char *cipher) {
    void *cipher_text_mem;
    struct file_memory_map_meta cipher_text_meta;
    open_source_file_memory_mapped(cipher_text_path, &cipher_text_mem, &cipher_text_meta);

    close_source_file_memory_mapped(&cipher_text_mem, &cipher_text_meta);
}

int main(int argc, char *argv[]) {
    int flag;
    while ((flag = getopt(argc, argv, "deh i:o:c:k:")) != -1) {
        switch (flag) {
            case 'd':
                printf("Decrypt");
                break;
            default:
                printf("Usage %s -<MODE>\n", argv[0]);
                printf("\t<MODE>: d Decrypt aka Aufgabe 1: <in_file_path> <out_file_path> <key_iv_path>\n");
                printf("\t\t e Encrypt aka Aufgabe 3");
                printf("")
                return EXIT_FAILURE;
                break;
        }
    }

    return EXIT_SUCCESS;
}
