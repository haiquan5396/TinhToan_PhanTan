/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
#include <openssl/md5.h>
#include <stdio.h>
#include <string.h>
#include <openssl/hmac.h>
#include <errno.h>


char *md5(const char *string){
    
    unsigned char *digest = (unsigned char*)malloc(16);

    MD5_CTX context;
    MD5_Init(&context);
    MD5_Update(&context, string, strlen(string));
    MD5_Final(digest, &context);
    char *converted_to_string = (char*)malloc(33);
    for(int i = 0; i < 16; ++i)
        sprintf(&converted_to_string[i*2], "%02x", (unsigned int)digest[i]);

    return converted_to_string;

}

int main(void)
{
    char password[100];
    printf("Enter your password: ");
    scanf("%s", password);
    printf("Your Name is: %s\n", password);
    printf("Your MD5 is: %s\n", md5(password));
    return 0;
}