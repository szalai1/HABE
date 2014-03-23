#include <pbc.h>
#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>

typedef struct string string;

struct string {
	char* str;
	size_t size;
};

string string_init(size_t size) {
	string ret;
	ret.str = (char* ) malloc(size);
	ret.size = size;
	return ret;	
}

string string_from_cstring(char* s ) {
	string ret;
	ret.size = strlen(s);
	ret.str = (char*) malloc(ret.size);
	strcpy(ret.str, s);
	return ret;
}

	


//generae a 128bit hash from element
// RETURN 33 bytes long char[]
char*  hash_to_string(element_t element) {
	//convert elemnt to sztring
	int i;
	char buff[1024];
	element_snprintf(buff,1024,"%B",element);
	//printf("%s \n [ %d ] \n\n", buff, strlen(buff));

	
	unsigned char hash[MD5_DIGEST_LENGTH + 1];
	char ret[33];
	MD5((unsigned char*)& buff, strlen(buff), (unsigned char*)&hash);
	for(i = 0; i < 16; ++i) {
		sprintf(ret + i*2, "%02x", (unsigned int) hash[i]);
	}
	hash[17] = '\0';
//	printf("%s\n", hash);
	return ret;
	
}


typedef struct params params;

struct params {
	element_t generator;
	element_t n;
	element_t P_0;
	element_t Q_0;
	
	
};




int main(void){
	pairing_t pairing;
	char param[1024];
	char* out;
	size_t count = fread(param, 1, 1024, stdin);
	if (!count) pbc_die("input error");
	pairing_init_set_buf(pairing, param, count);
	element_t g, h;
	element_t public_key, secret_key;
	element_t sig;
	element_t temp1, temp2;;
	element_init_G2(g, pairing);
	element_init_G2(public_key, pairing);
	element_init_G1(h, pairing);
	element_init_G1(sig, pairing);
	element_init_GT(temp1, pairing);
	element_init_GT(temp2, pairing);
	element_init_Zr(secret_key, pairing);
	element_random(g);

	element_random(secret_key);
	
	
	element_pow_zn(public_key, g, secret_key);
	
	element_from_hash(h, "ABCDEF", 6);

	element_pow_zn(sig, h, secret_key);

	out = hash_to_string(h);
	printf("%s\n", out);
	
	
	return 0;
}


