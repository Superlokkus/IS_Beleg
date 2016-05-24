/*! @file s70357.c
 * IS_Beleg by Markus Klemm
 * */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <openssl/evp.h>

int main (int argc, char* argv[]){
    if (argc != 1+ 3){
        printf("Usage %s",argv[0]);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
