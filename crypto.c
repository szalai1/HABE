#include <pbc.h>
#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>
#include "hashs.h"

typedef struct public_key public_key;
typedef struct params params;

unsigned int CHILDREN_NUM;



struct public_key {
	unsigned int* ID_tuple;
	unsigned int level;	
};

public_key init_public_key(public_key* parent) {
	if(parent == NULL) {
		public_key ret;
		ret.level = 0;
		ret.ID_tuple = (unsigned int*) malloc(sizeof(unsigned int));
		ret.ID_tuple[0] = 0;
		return ret;
	}
	else {
		public_key ret;
		ret.level = parent->level + 1;
		ret.ID_tuple = (unsigned int*) malloc(sizeof(unsigned int) *
																					(ret.level + 1));
		int i;
		for(i = 0; i < ret.level + 1; ++i) {
			ret.ID_tuple[i] = parent->ID_tuple[i];
 		}
		ret.ID_tuple[ret.level] = CHILDREN_NUM;
		return ret;	
	}
	
}

void create_DM(element_t MK, public_key p ) {
	//todo;
}


struct params{
	element_t P_0;
	element_t Q_0;
};

void init_params(params* param, pairing_t* pairing) {
	element_init_G1(param->P_0, *pairing);
	element_init_G1(param->Q_0, *pairing);
}

void SETUP(params* param, element_t* secret_key, pairing_t* pairing) {
	init_params(param, pairing);
	element_init_Zr(*secret_key, *pairing);
	element_random(param->P_0); //setup paramas and the secret key
	element_random(*secret_key);
	element_mul(param->Q_0, *secret_key, param->P_0);
}




int main(void){
	pairing_t pairing;
	char param[1024];
	char out[33];
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
	
	element_from_hash(g,"ASD",3);
	H_2(g);
	element_random(secret_key);
	params par;
	init_params(&par, &pairing);

	
	
	return 0;
}
