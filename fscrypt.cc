//Block cipher method blowfish

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fscrypt.h"


BF_KEY *key;
unsigned char initial_vector[]="00000000";

//Encryption
void *fs_encrypt(void *plaintext, int bufsize, char *keystr, int *resultlen){

	
	int i , padding_size, ciphertext_size, size;
	unsigned char *plaintext_main = (unsigned char *) plaintext;
	unsigned char * in = (unsigned char *)malloc(sizeof(unsigned char) * BLOCKSIZE);
	unsigned char * out = (unsigned char *)malloc(sizeof(unsigned char) * BLOCKSIZE);
	key = (BF_KEY *)malloc(sizeof(BF_KEY));

	//setting up the BF_key
	BF_set_key(key, strlen(keystr), (const unsigned char *)keystr);

	//Finding the size of the ciphertext
	if (bufsize % BLOCKSIZE != 0){
		ciphertext_size = bufsize + (bufsize % BLOCKSIZE);	
	}
	
	else {	
		ciphertext_size = bufsize;	
	}
		
	unsigned char * ciphertext = (unsigned char *)malloc(sizeof(unsigned char) * ciphertext_size);

	for(i=0;i< bufsize;i++){	
		ciphertext[i]='0';
	}

	for (i = 0; i < BLOCKSIZE; i++){
		in[i] = initial_vector[i];
		out[i] = '0';
	}
	
	size=bufsize;

	//doing xoring
	while( size >= BLOCKSIZE){
		for(i = 0; i < BLOCKSIZE; i++){
			in[i]=in[i] ^ (unsigned char)(plaintext_main[bufsize - size + i]);
		}
		
		BF_ecb_encrypt(in, out, key, BF_ENCRYPT);

		for(i = 0; i < BLOCKSIZE; i++){
			in[i] = out[i];
			ciphertext[bufsize - size + i] = out[i];
		}
		
		size = size - BLOCKSIZE;
	}



	padding_size = BLOCKSIZE - size ;

	*resultlen = bufsize - size ;

	if(size > 0){
		for(i = 0; i < BLOCKSIZE; i++){
			if(size != 0){
				in[i]= in[i] ^ (unsigned char)plaintext_main[bufsize - size ];
				size --;
			}
			else{
				in[i]= in[i] ^ (unsigned char)(padding_size & 0xFF);	
			}			
		}

		BF_ecb_encrypt(in, out, key, BF_ENCRYPT);

		for(i = 0; i < BLOCKSIZE; i++){
			ciphertext[bufsize - BLOCKSIZE + padding_size + i] = out[i];
		}

		*resultlen = *resultlen + BLOCKSIZE;		
	}

	free(key);
	free(in);
	free(out);
	return (void *)ciphertext;	//returning the encrypted ciphertext to main.cc
}


//Decryption
void *fs_decrypt(void *ciphertext, int bufsize, char *keystr, int *resultlen){	
	
	int i, padding_size, size, counter=0;
	unsigned char *ciphertext_main=(unsigned char *) ciphertext; 
	unsigned char * plaintext = (unsigned char *)malloc(sizeof(unsigned char) * (bufsize));
	unsigned char * in = (unsigned char *)malloc(sizeof(unsigned char) * BLOCKSIZE);
	unsigned char * out = (unsigned char *)malloc(sizeof(unsigned char) * BLOCKSIZE);
	unsigned char * temp= (unsigned char *)malloc(sizeof(unsigned char) * BLOCKSIZE);
	
	key=(BF_KEY *)malloc(sizeof(BF_KEY));

	//setting up the BF_key
	BF_set_key(key, strlen(keystr), (const unsigned char *)keystr);
	
	for(i=0;i< bufsize;i++){	
		plaintext[i]='0';
	}

	for (i = 0; i < BLOCKSIZE; i++){
		in[i] = '0';
		out[i] = '0';
		temp[i] = initial_vector[i];	
	}

	size = bufsize;

	while(size  >= BLOCKSIZE){
		for(i = 0; i < BLOCKSIZE; i++){
			in[i] = (unsigned char)ciphertext_main[bufsize - size + i];			
		}
		
		BF_ecb_encrypt(in, out, key, BF_DECRYPT);

		//doing xoring
		for(i = 0; i < BLOCKSIZE; i++){
			out[i]= out[i] ^ temp[i];
			temp[i] = in[i];
			plaintext[bufsize - size + i] = out[i];
		}		
		size = size - BLOCKSIZE;
	}

	for (i = bufsize - 1; i > bufsize - BLOCKSIZE + 1; i--){		
		if(plaintext[bufsize - 1] == plaintext[i - 1]){
			counter ++;
		}
		else{
			break;
		}
	}
		
	if((counter+1) >= (int)(plaintext[bufsize - 1])){
		*resultlen = bufsize - (int)(plaintext[bufsize - 1]);
	}
	else{
		return NULL;
	}

	free(key);
	free(in);
	free(temp);
	free(out);
	return (void *)plaintext;  //returning the decrypted plaintext to main.cc
}