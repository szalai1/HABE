#include <pbc.h>
#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>
#include "hashs.h"
#include "crypto.h"
//master_key is an element from Z_q
// is an element from G_1


void init_params(params* param) {
	element_init_G1(param->P_0, pairing);
	element_init_G1(param->Q_0, pairing);
}

void free_params(params* param) {
	if(param == NULL) { return; }
	element_clear(param->P_0);
	element_clear(param->Q_0);
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
		++CHILDREN_NUM;
		return ret;
	}
}

void free_public_key(public_key* pk) {
  free(pk->ID_tuple);
}



//init and gen new valaid Q_tuple
//MALLOC ALERT! use free_Q_tuple
Q_tuple init_Q_tuple(Q_tuple* parent, element_t mk_i, params params) {
	Q_tuple ret;
	//set Q = mk_i * P_0
	element_t Q;
	
	element_init_same_as(Q, params.Q_0);
	element_mul_zn(Q, params.P_0, mk_i);
	element_printf("%B\n\n%B\n", Q, params.P_0);
	//in case of RM
	if(parent == NULL ) {
		ret.length = 1;
		ret.Q_tuple = (element_t *) malloc(sizeof(element_t));
		element_init_same_as(ret.Q_tuple[0],params.Q_0);
		element_set(ret.Q_tuple[0], params.Q_0);
		printf("NULL\n\n");
	}
	else {
		int i =0;
		ret.length = parent->length + 1;
		ret.Q_tuple = (element_t *) malloc(sizeof(element_t) *
																			 (parent->length + 1));
		//copy the tuple
		for(i = 0; i < ret.length; ++i) {
			element_init_same_as(ret.Q_tuple[i], (parent->Q_tuple)[i]);
			element_set(ret.Q_tuple[i], (parent->Q_tuple)[i]);			
		}
		//the last element is Q
		element_init_same_as(ret.Q_tuple[ret.length], Q);
		element_set(ret.Q_tuple[ret.length], Q);		
	}
	element_clear(Q);
	return ret;
}

void free_Q_tuple(Q_tuple tuple) {
	int i;
	for(i = 0; i < tuple.length; ++i) {
		element_clear(*(tuple.Q_tuple));
	}
	free(tuple.Q_tuple);
}




//MALLOC ALERT! use free master_key
//MK is masterkey of parent DM
//INPUT: parent master_key: MK 
//RETUNR new DM master keys
master_key create_DM(master_key MK, public_key p, params param) {
	//init masterkey of the child DM
	master_key ret;
	element_t temp, temp1;
	element_init_G1(temp, pairing);
	ret.mk = (element_t* ) malloc(sizeof(element_t));
	ret.S = (element_t *) malloc(sizeof(element_t));
	element_init_same_as(*(ret.mk), *(MK.mk));
	element_init_same_as(*(ret.S),*(MK.S));
	element_random(*(ret.mk));
	ret.Q_tuple = init_Q_tuple(&(MK.Q_tuple), *(ret.mk), param);
	ret.S = (element_t*) malloc(sizeof(element_t));
	// S_i+1 = S_i + mk_i * H_1( PK_i+1)
	//element_from_hash needs char*, so i had to do a trick
	element_from_hash(temp, (char*) p.ID_tuple,
										sizeof(int) *	(p.level + 1) / sizeof(char) );
	element_init_same_as(temp1, temp);
	element_mul_zm(temp1, temp, *(MK.mk));
	element_add(*(ret.S), *(MK.S), temp1);
	element_clear(temp1);
	element_clear(temp);
	return ret;
}

void free_master_key(master_key mk) {
	element_clear(*(mk.mk));
	element_clear(*(mk.S));
	free(mk.mk);
	free(mk.S);
	free_Q_tuple(mk.Q_tuple);	
}

//MALLOC ALERT!!! use free_master_key;
master_key SETUP(params* param, element_t* secret_key) {
	master_key RM;//RootMaster
	init_params(param);
	element_init_Zr(*secret_key, pairing);
	element_random(param->P_0); //setup paramas and the secret key
	element_random(*secret_key);
	element_mul(param->Q_0, *secret_key, param->P_0);
	//root master own MK
	RM.mk = (element_t* ) malloc(sizeof(element_t));
	RM.S = (element_t*) malloc(sizeof(element_t));
	element_init_same_as(*(RM.mk), *secret_key);
	element_set(*(RM.mk), *secret_key);
	
	element_init_G1(*(RM.S), pairing);
	//in an additive group the null element is the identity, a + 0 = a
	element_set0(*(RM.S));
	element_printf("%B\n",*secret_key);
	RM.Q_tuple = init_Q_tuple(NULL, *secret_key, *param);

	return RM;
}

