#include <pbc.h>
#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>
#include "hashs.h"
struct params;
typedef struct public_key public_key;
typedef struct params params;
typedef struct Q_tuple Q_tuple;
typedef struct master_key master_key;
pairing_t pairing;

unsigned int CHILDREN_NUM;

struct public_key {
	unsigned int* ID_tuple;
	unsigned int level;
};

struct params{
	element_t P_0;
	element_t Q_0;
};

void init_params(params* param) {
	element_init_G1(param->P_0, pairing);
	element_init_G1(param->Q_0, pairing);
}



//in case of rootmaster the input parameter !is NULL
// else parant of next node parameter pointer
//generate new unique public key from global variable CHILDREN_NUM;
//MALLOC ALERT!! use free_public_key
//return: i+1th  public_key

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

void free_public_key(public_key* pk) {
  free(pk->ID_tuple);
}

struct Q_tuple {
	element_t* Q_tuple;
	unsigned int length;
};

//init and gen new valaid Q_tuple
//MALLOC ALERT! use free_Q_tuple
Q_tuple init_Q_tuple(Q_tuple* parent, element_t mk_i, params params) {
	Q_tuple ret;
	//set Q = mk_i * P_0
	element_t Q;
	element_init_same_as(Q, params.Q_0);
	element_mul(Q, mk_i, params.P_0);
	//in case of RM
	if(parent == NULL ) {
		ret.length = 1;
		ret.Q_tuple = (element_t *) malloc(sizeof(element_t));
		element_set(ret.Q_tuple[0], params.Q_0);
	}
	else {
		int i =0;
		ret.length = parent->length + 1;
		ret.Q_tuple = (element_t *) malloc(sizeof(element_t) *
																			 parent->length + 1);
		//copy the tuple
		for(i = 0; i < ret.length; ++i) {
			element_init_same_as(ret.Q_tuple[i], (parent->Q_tuple)[i]);
			element_set(ret.Q_tuple[i], (parent->Q_tuple)[i]);			
		}
		//the last element is Q
		element_init_same_as(ret.Q_tuple[ret.length], Q);
		element_set(ret.Q_tuple[ret.length], Q);		
	}
	return ret;
}

void free_Q_tuple(Q_tuple tuple) {
	free(tuple.Q_tuple);
}

struct master_key {
	element_t* mk;
	Q_tuple Q_tuple;
	element_t* S; 
  };  

master_key create_DM(master_key MK, public_key p,params param) {
	//init masterkey sub variables
	master_key ret;
	ret.mk = (element_t* ) malloc(sizeof(element_t));
	ret.S = (element_t *) malloc(sizeof(element_t));
	element_init_same_as(*(ret.mk), *(MK.mk));
	element_init_same_as(*(ret.S),*(MK.S));
	element_random(*(ret.mk));
	ret.Q_tuple = init_Q_tuple()
	
	
	
}


void SETUP(params* param, element_t* secret_key) {
	init_params(param);
	element_init_Zr(*secret_key, pairing);
	element_random(param->P_0); //setup paramas and the secret key
	element_random(*secret_key);
	element_mul(param->Q_0, *secret_key, param->P_0);
}




int main(void){
	
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
	init_params(&par);



	return 0;
}
