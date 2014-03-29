#include <pbc.h>
#include <openssl/md5.h>
#include <string.h>
#include "hashs.h"

//H_mki function from the article
//unique hash function from bit string to Z_r
//like HAMC H_A(mk_i | MD5(X | mk_i)) where H_A is H_3, mk_i = key
void H_4(element_t* out, element_t key, char* string ) {
	int buff_size;
	//key to string;
	int element_length = element_length_in_bytes(key);
	if (strlen(string) < MD5_DIGEST_LENGTH ) {
		buff_size = MD5_DIGEST_LENGTH + element_length;
	}
	else {
		buff_size = strlen(string) + element_length;
	}
	unsigned char element_in_bytes[element_length + 1];
	element_to_bytes(element_in_bytes, key);
	element_in_bytes[element_length] = '\0';
	//concatanation X | mk_i := buff
	int buff[buff_size];
	strcpy(buff, string);
	strcpy(buff + strlen(string), element_in_bytes);
	buff[strlen(string) + element_length] = '\0';
	// compute MD5 of buff;
	unsigned char hash[MD5_DIGEST_LENGTH + 1];
	MD5(buff, strlen(string) + element_length, hash);
	hash[MD5_DIGEST_LENGTH] = '\0';
	//mk_i | hash to buff
	strcpy(buff, element_in_bytes);
	strcpy(buff + element_length, hash);
	buff[element_length + MD5_DIGEST_LENGTH] = '\0';
	//compute H_A := H3 to get elemenet from Z_r
	H_3(*out, buff, element_length + MD5_DIGEST_LENGTH );	
}

//generae a 128bit hash from element
// RETURN 33 bytes long char[]
// MALLOC : RET !!!!!!!
char*  H_2(element_t element) {
	//convert elemnt to sztring
	int i;
	int element_length = element_length_in_bytes(element);
	unsigned char buff[element_length + 1];
	element_to_bytes(buff, element);
	buff[element_length] = '\0';
	//hash the string
	unsigned char hash[MD5_DIGEST_LENGTH];
	MD5(buff, element_length, hash);
	//write the hash of string into a string (ret)
	char* ret = malloc(sizeof(char)*33);
	for(i = 0; i < 16; ++i) {
		sprintf(ret + i*2, "%02x", (unsigned int) hash[i]);
	}
	ret[33] = '\0';
	return  ret ;
}
