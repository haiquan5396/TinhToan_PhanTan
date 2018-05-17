	
#include <openssl/md5.h>
#include <stdio.h>
#include <string.h>
#include <openssl/hmac.h>
#include <mpi.h>
#include <math.h>
#include <time.h>


const int ALPHABET_LEN = 26;
//const int PASSWORD_LEN = 6; 


char alphabet[] = {'a','b','c','d', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'}; 

char *md5(const char *string){
    
    unsigned char *digest = (unsigned char*)malloc(16);

    MD5_CTX context;
    MD5_Init(&context);
    MD5_Update(&context, string, strlen(string));
    MD5_Final(digest, &context);
    char *converted_to_string = (char*)malloc(33);
    for(int i = 0; i < 16; ++i)
        sprintf(&converted_to_string[i*2], "%02x", (unsigned int)digest[i]);
    free(digest);
    return converted_to_string;

}

char *convert_int_to_string(unsigned long number, int password_len){
    char temp_char;
    int position_char;
    char *string = (char*)calloc(password_len, sizeof(char));

    for(int i = 0; i< password_len; i++){
        position_char = number % ALPHABET_LEN;
        temp_char = alphabet[position_char];
        string[i] = temp_char;
        number = number/ALPHABET_LEN;
    }
    return string;
    
}


int rank0(){

    char *hashed_password = (char *)malloc(33);
    printf("Enter your MD5: ");
    scanf("%s", hashed_password);
    printf("Your MD5 is: %s\n", hashed_password);
    char processor_name[MPI_MAX_PROCESSOR_NAME];
    int name_len;
    MPI_Get_processor_name(processor_name, &name_len);  
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC_RAW, &start);
    
    int np; 
    unsigned long max_number, end_number; 
    
    MPI_Comm_size(MPI_COMM_WORLD, &np);
    MPI_Status status; 
    
    for(int i = 1 ; i< np; i++){
        // Send hashed password
        MPI_Send(hashed_password, 33, MPI_CHAR, i, 1, MPI_COMM_WORLD);
    }
    
    int done = 0;
    unsigned long result;
    MPI_Request request;
    MPI_Irecv(&result,1,MPI_UNSIGNED_LONG,MPI_ANY_SOURCE,4,MPI_COMM_WORLD,&request);
    MPI_Test(&request,&done,&status);
    
    
    for (int password_len = 1; password_len <= ALPHABET_LEN; password_len++ ){
        max_number = (unsigned long)pow(ALPHABET_LEN, password_len);
        unsigned long number = 0;
        end_number = max_number/np;
        
        while (!done) {
            if (number < end_number) {
                char *string = convert_int_to_string(number, password_len);
                char *data_md5;
                data_md5 = md5(string);
                if(strcmp(data_md5, hashed_password) == 0){

                    printf("The PASSWORD is found in rank 0 (%s): %s \n", processor_name ,string);
                    for(int i = 0; i< np; i++){
                        MPI_Send(&number,1,MPI_UNSIGNED_LONG,i, 4,MPI_COMM_WORLD);
                    }
                    done = 1;
                }
                ++number;
                free(string);
                free(data_md5);
            }else{
                break;
            }

            MPI_Test(&request,&done,&status);
        }
        
        if(done == 1){
            break;
        }
        
    }
    
    clock_gettime(CLOCK_MONOTONIC_RAW, &end);
    double delta_us = (end.tv_sec - start.tv_sec)*1000000 + (end.tv_nsec - start.tv_nsec) / 1000;
    printf("Time: %f second\n",delta_us/1000000);
    return 0; 
}

int ranki(){
    char *hashed_password = (char *)malloc(33);
    MPI_Status status; 
    int np;
    MPI_Comm_size(MPI_COMM_WORLD, &np);
    char processor_name[MPI_MAX_PROCESSOR_NAME];
    int name_len;
    MPI_Get_processor_name(processor_name, &name_len);  

    MPI_Recv(hashed_password, 33, MPI_CHAR, 0, 1, MPI_COMM_WORLD, &status);
    
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    
    int done = 0;
    unsigned long result;
    MPI_Request request;
    MPI_Irecv(&result,1,MPI_UNSIGNED_LONG,MPI_ANY_SOURCE,4,MPI_COMM_WORLD,&request);
    MPI_Test(&request,&done,&status);
    
    unsigned long max_number, end_number, start_number; 
    
    for (int password_len = 1; password_len <= ALPHABET_LEN && done == 0; password_len++ ){
        max_number = (unsigned long)pow(ALPHABET_LEN, password_len);
        start_number = (max_number/np)*rank;
        if (rank == (np -1)){
            end_number = max_number;
        }else{
            // max_number/np is total number must compare
            end_number = start_number + max_number/np;
        }
        
        unsigned long number = start_number;
         
        while (!done) {
            if (number < end_number) {
                char *string = convert_int_to_string(number, password_len);
                char *data_md5;
                data_md5 = md5(string);
                if(strcmp(data_md5, hashed_password) == 0){
                    printf("The PASSWORD is found in rank %d (%s): %s \n", rank, processor_name ,string);
                    for(int i = 0; i< np; i++){
                        MPI_Send(&number,1,MPI_UNSIGNED_LONG,i,4,MPI_COMM_WORLD);
                    }
                    return 0;
                }
                ++number;
                free(string);
                free(data_md5);
            }else{
                break;
            }
            MPI_Test(&request,&done,&status);
        }
        if(done == 1){
            break;
        }
    }
    
    return 0;
}

int main(int argc, char ** argv){
         
    int rank;
        
    MPI_Init(&argc, &argv);

    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    if (rank == 0)
        rank0();
    else
        ranki();
    
    MPI_Finalize();    
}
