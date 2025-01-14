#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include "log_pwd.h"
#include "misc.h"

static int seek=0;
static int count=-1;
static int last=-1;

static char *skey_encrypted_filename = ""RSA_SKEY_ENCRYPTED_FILENAME;
static char *skey_filename = ""RSA_SKEY_FILENAME;
static char *logfile = ""ENCRYPTED_OUTPUT_FILENAME;

static char usagestring[] = "Usage: %s <-s seek_distance_records> <-c num_records_to_read> <-l last_n_records_to_read> <-logfile rsa_encrypted_log_file> <-aespemfile aes_encrypted_rsa4096_pem_file> <-pemfile rsa4096_pem_file>\n";

int main(int argc, char **argv){
	//parse arguments
	if(argc == 2 && (strcmp(argv[1],"--help") == 0 || strcmp(argv[1],"-h") == 0 || strcmp(argv[1],"-H") == 0)){
		printf(usagestring,argv[0]);
		return 0;
	}
	for(int i=1;i<argc;i+=2){
		if(strcmp(argv[i],"-s") == 0){
			if(i+1 < argc)
				seek = atoi(argv[i+1]);
			else{
				fprintf(stderr,usagestring,argv[0]);
				exit(1);
			}
		}else if(strcmp(argv[i],"-c") == 0){
			if(i+1 < argc)
				count = atoi(argv[i+1]);
			else{
				fprintf(stderr,usagestring,argv[0]);
				exit(1);
			}
		}
		else if(strcmp(argv[i],"-l") == 0){
			if(i+1 < argc)
				last = atoi(argv[i+1]);
			else{
				fprintf(stderr,usagestring,argv[0]);
				exit(1);
			}
		}
		else if(strcmp(argv[i],"-aespemfile") == 0){
			if(i+1 < argc)
				skey_encrypted_filename = argv[i+1];
			else{
				fprintf(stderr,usagestring,argv[0]);
				exit(1);
			}
		}
		else if(strcmp(argv[i],"-pemfile") == 0){
			if(i+1 < argc)
				skey_encrypted_filename = argv[i+1];
			else{
				fprintf(stderr,usagestring,argv[0]);
				exit(1);
			}
		}else if(strcmp(argv[i],"-logfile") == 0){
			if(i+1 < argc)
				logfile = argv[i+1];
			else{
				fprintf(stderr,usagestring,argv[0]);
				exit(1);
			}
		}else{
			fprintf(stderr,usagestring,argv[0]);
			exit(1);
		}
	}
	
	//check for ssh_log_skey.pem.aes256
	//	if it exists then ask for key and decrypt it
	//	then load decrypted aes256 file into key
	//otherwise
	//	check for skey_filename
	//	if it exists then load into key
	//else
	//	print plaintext log
	FILE *fd;
	EVP_PKEY *key = NULL;
	if((fd = fopen(skey_encrypted_filename,"rb")) != NULL){
		//decrypt the file then load into EVP_PKEY *key
		//read encrypted secret key file
		char ciphertext[4096];
		
		//get user input password
		char prompt[] = "Enter password: ";
		char *password = read_passphrase(prompt,RP_ALLOW_STDIN);
		if(password == NULL){
			fprintf(stderr,"read_passphrase failed\n");
			exit(-1);
		}
		//derive AES key from password
		//1000 iterations PBKDF2 with SHA1 -> key for AES-256 CBC mode
		unsigned char test[8];
		fread(test,8,1,fd);
		if(memcmp(test,"Salted__",8) != 0){
			fprintf(stderr,"No salt detected for PBKDF2\nMake sure the encryption file \"%s\" is setup properly\n",skey_encrypted_filename);
			exit(-1);
		}
		unsigned char salt[8];
		fread(salt,8,1,fd);
		unsigned char aes_key[32];
		if(PKCS5_PBKDF2_HMAC_SHA1(password,strlen(password),salt,8,1000,32,aes_key) == 0){
			fprintf(stderr,"No salt detected for PBKDF2\nMake sure the encryption file \"%s\" is setup properly\n",skey_encrypted_filename);
			exit(-1);
		}
		if(password != NULL)
			free(password);

		//iv used for cbc mode is all zeroes
		//no iv reuse (one file) so this should be fine
		char iv[] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
		
		//read rsa skey file
		int ciphertext_len = fread(ciphertext,1,4096,fd);
		fclose(fd);
		
		//initialize EVP_CIPHER class
		EVP_CIPHER_CTX *ctx;
		int len,plaintext_len;
		if(!(ctx = EVP_CIPHER_CTX_new())){
			fprintf(stderr,"Error creating AES encryption class: EVP_CIPHER_CTX_new\n");
			exit(-1);
		}
		if(EVP_DecryptInit_ex(ctx,EVP_aes_256_cbc(),NULL,aes_key,iv) != 1){
			fprintf(stderr,"Error creating AES encryption class: EVP_EncryptInit_ex\n");
			exit(-1);
		}
		char rsa_skey[4096];
		if(EVP_DecryptUpdate(ctx,rsa_skey,&len,ciphertext,ciphertext_len) != 1){
			fprintf(stderr,"Decryption failed. Did you enter the password correctly?\n");
                        exit(-1);
		}
		plaintext_len = len;
		if(EVP_DecryptFinal_ex(ctx,rsa_skey+len,&len) != 1){
			fprintf(stderr,"Decryption failed. Did you enter the password correctly?\n");
                        exit(-1);
		}
		plaintext_len += len;
		if(plaintext_len > 4096){
			fprintf(stderr,"Unexpected plaintext length\n");
			exit(-1);
		}
		rsa_skey[plaintext_len-1] = '\0';
		EVP_CIPHER_CTX_free(ctx);
		
		//load RSA private key into EVP_PKEY *key
		BIO *bio = BIO_new_mem_buf((void*)rsa_skey,-1);
		if(bio == NULL){
			fprintf(stderr,"BIO_new_mem_buf failed\n");
			exit(-1);
		}
		key = PEM_read_bio_PrivateKey(bio,NULL,NULL,NULL);
		BIO_free(bio);
		if(key == NULL){
			fprintf(stderr,"Invalid RSA private key from \"%s\". Is the file encrypted correctly?\n",skey_encrypted_filename);
			exit(-1);
		}
		printf("\x1b\x5b\x41\x1b\x5b\x4b");
	}else if((fd = fopen(skey_filename,"rb")) != NULL){
		key = PEM_read_PrivateKey(fd,NULL,NULL,NULL);
		fclose(fd);
		if(key == NULL){
			fprintf(stderr,"Unable to read PEM file: %s\n",skey_filename);
			exit(-1);
		}
	}else if((fd = fopen(PLAINTEXT_OUTPUT_FILENAME,"rb")) != NULL){
		//print entire log
		int c;
		while((c = fgetc(fd)) != EOF)
			putchar(c);
		fclose(fd);
		return 0;
	}else{
		fprintf(stderr,"Unable to read log file: "PLAINTEXT_OUTPUT_FILENAME"\n");
		exit(-1);
	}
	
	//read data from encrypted log file
	FILE *cipher_fd = fopen(logfile,"rb");
	if(cipher_fd == NULL){
		fprintf(stderr,"Unable to open encrypted log file: %s\n",logfile);
		exit(-1);
	}
	//seek options set by command line -- only read part of the encrypted logs (saves time)
	//only seeks based on what the variables "last" and "seek" are initialized to
	if(last != -1){
		fseek(cipher_fd,-512*last,SEEK_END);
	}else if(seek != -1){
		fseek(cipher_fd,512*seek,SEEK_SET);
	}
	char buffer[512];
	//initialize EVP class
	if(key == NULL){
		fprintf(stderr,"EVP_PKEY initialization failed\n");
		exit(-1);
	}
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key,NULL);
	if(ctx == NULL){
		fprintf(stderr,"EVP_PKEY_CTX initialization failed\n");
                exit(-1);
	}
	if(EVP_PKEY_decrypt_init(ctx) <= 0){
		fprintf(stderr,"EVP_PKEY_decrypt_init failed\n");
                exit(-1);
	}
	if(EVP_PKEY_CTX_set_rsa_padding(ctx,RSA_PKCS1_OAEP_PADDING) <= 0){
		fprintf(stderr,"EVP_PKEY_CTX_set_rsa_padding failed\n");
                exit(-1);
	}
	
	//display the log file
	while(fread(buffer,512,1,cipher_fd) > 0){
		//only read "count" number of records
		if(count == 0)
			break;
		count--;
		size_t outlen = 512;
		char plaintext[512];
		int status = EVP_PKEY_decrypt(ctx,plaintext,&outlen,buffer,512);
		if(status != 1){
			fprintf(stderr,"EVP_PKEY_decrypt failed with status %d\n",status);
			exit(-1);
		}
		for(size_t i=0;i<outlen;i++)
			printf("%c",plaintext[i]);	
	}
	EVP_PKEY_CTX_free(ctx);
	fclose(cipher_fd);
	
	return 0;
}
