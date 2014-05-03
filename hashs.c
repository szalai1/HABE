#include <pbc.h>
#include <openssl/md5.h>
#include <string.h>
#include "hashs.h"
#include "crypto.h"


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
	char buff[buff_size];
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
unsigned char*  H_2(element_t element) {
	//convert elemnt to sztring
	int element_length = element_length_in_bytes(element);
	unsigned char buff[element_length];
	element_to_bytes(buff, element);
	//hash the string
	unsigned char* hash = (unsigned char*) malloc(MD5_DIGEST_LENGTH * sizeof( unsigned char)) ;
	MD5(buff, element_length, hash);
	return  hash ;
}

void Hmki(element_t* out, public_key pk, element_t* key) {
	// pk and key check
	element_init_Zr(*out, pairing);
	int len = (pk.level + 1) * sizeof(unsigned int) / sizeof(char);
	element_t x;
	element_init_G1(x,pairing);
	element_from_hash(x, pk.ID_tuple, len);
	len = element_length_in_bytes(x);
	unsigned char* str = (unsigned char* ) malloc(len);
	element_to_bytes(str, x);
	int len1  = element_length_in_bytes(*key);
	unsigned char* key_str = (unsigned char*) malloc(len1);
	element_to_bytes(key_str, *key);
	unsigned char* sum = (unsigned char*) malloc(len1 + len);
	memcpy(sum, str, len);
	memcpy(sum + len, key_str, len1);
	element_clear(x);
	free(str);
	free(key_str);
	unsigned char o[MD5_DIGEST_LENGTH + 1];
	MD5(sum, len + len1, o);
	o[MD5_DIGEST_LENGTH] = '\0';
	element_from_hash(*out, o, MD5_DIGEST_LENGTH);
	/////////////////////////	
}

void H_A(element_t* out, public_key pk) {
	element_init_Zr(*out, pairing);
	int len = (pk.level + 1) * sizeof(unsigned int) / sizeof(char);
	unsigned char o[MD5_DIGEST_LENGTH];
	MD5((unsigned char*) pk.ID_tuple, len, o);
	element_from_hash(*out, (unsigned char*) o, MD5_DIGEST_LENGTH);
}

void H_pk_to_G1(element_t* out, public_key pk) {
	element_init_G1(*out, pairing);
	int len = (pk.level + 1) * sizeof(unsigned int) / sizeof(char);
	unsigned char o[MD5_DIGEST_LENGTH];
	MD5((unsigned char*) pk.ID_tuple, len, o);
	element_from_hash(*out, (unsigned char*) o, MD5_DIGEST_LENGTH);
}




/* int main( ) { */
/* 	element_t mk; */
/* 	set_up_comm(); */
/* 	element_init_G1(mk, pairing); */
/* 	//element_random(mk); */

/* 	unsigned int tomb[4] = {1, 2, 4, 111132}; */
/* 	int len = sizeof(unsigned int) / sizeof(char); */
/* 	unsigned char out[MD5_DIGEST_LENGTH + 1]; */
/* 	MD5((unsigned char*) tomb, len * 4, out ); */
/* 	out[MD5_DIGEST_LENGTH] = '\0'; */
/* 	element_from_hash(mk, out, MD5_DIGEST_LENGTH); */
/* 	element_printf("%B\n",mk); */
	
/* 	return 0; */
	
/* } */

