/*! @file s70357.c
 * IS_Beleg by Markus Klemm
 * */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <openssl/evp.h>


/*!
 * @param cipher_text Buffer, at least (plain_len + cipher_block_size - 1) bytes big,
 * where the encrypted data will be stored.
 * @param cipher_text_len Actual length of encrypted data in cipher_text in bytes
 */
bool mk_evp_encrypt(const unsigned char *plain_text,
                    const int plain_len,
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
    if (!EVP_EncryptUpdate(context, cipher_text, cipher_text_len, plain_text, plain_len)) {
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

void decrypt(FILE *cipher_text, FILE plain_text, FILE *key, int corrupt_byte_pos, int corrupt_byte_count) {

}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage %s -<MODE>\n", argv[0]);
        printf("\t<MODE>: d Decrypt aka Aufgabe 1\n");
        return EXIT_FAILURE;
    }
    switch (*++argv[1]) {
        case 'd':

            break;
        default:
            break;
    }
    //EVP_des_ede_cbc

    return EXIT_SUCCESS;
}
