#include <pbc.h>
#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>
#include "hashs.h"
#include "crypto.h"
/*
	        O
		  	/	  \
      DM_1  LM_DM
   	 / | \
		/  A0 \ 
   O       O
 / | \     | \ 
A1 A2 O    U  A3

	 
 */
pairing_t pairing;
params PARAM;
unsigned int CHILDREN_NUM;

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
		for(i = 0; i < ret.level; ++i) {
			ret.ID_tuple[i] = parent->ID_tuple[i];
 		}
		ret.ID_tuple[ret.level] = get_next_id(parent);

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
	//in case of RM
	if(parent == NULL ) {
		ret.length = 1;
		ret.Q_tuple = (element_t *) malloc(sizeof(element_t));
		element_init_same_as(ret.Q_tuple[0],params.Q_0);
		element_set(ret.Q_tuple[0], params.Q_0);
	}
	else {
		
		int i =0;
		ret.length = parent->length + 1;
		ret.Q_tuple = (element_t *) malloc(sizeof(element_t) *
																			 (parent->length + 1));
		
		//copy the tuple
		for(i = 0; i < ret.length - 1; ++i) {
			element_init_same_as(ret.Q_tuple[i], (parent->Q_tuple)[i]);
			element_set(ret.Q_tuple[i], (parent->Q_tuple)[i]);
			
		}
		//the last element is Q
		element_init_same_as(ret.Q_tuple[ret.length - 1], Q);
		element_set(ret.Q_tuple[ret.length - 1], Q);
	}
	element_clear(Q);
	return ret;
}

void free_Q_tuple(Q_tuple tuple) {
	int i;
	for(i = 0; i < tuple.length; ++i) {
		printf("clear E \n");
		element_clear(tuple.Q_tuple[i]);
		printf("clear U \n");
	}
	printf("clear \n");
	free(tuple.Q_tuple);	
	printf("clear \n");
}




//MALLOC ALERT! use free master_key
//MK is masterkey of parent DM
//INPUT: parent master_key: MK 
//RETUNR new DM master keys
//p is public key of child
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
		// S_i+1 = S_i + mk_i * H_1( PK_i+1)
	//element_from_hash needs char*, so i had to do a trick
	element_from_hash(temp, (char*) p.ID_tuple,
										sizeof(int) *	(p.level + 1) / sizeof(char) );
	element_init_same_as(temp1, temp);
	element_mul_zn(temp1, temp, *(MK.mk));
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
	printf("free ms key \n");

	free_Q_tuple(mk.Q_tuple);
	
}

//MALLOC ALERT!!! use free_master_key;
master_key SETUP(params* param) {
	master_key RM;//RootMaster
	RM.mk = (element_t* ) malloc(sizeof(element_t));
	RM.S = (element_t*) malloc(sizeof(element_t));
	init_params(param);
	element_init_Zr(*(RM.mk), pairing);
	element_init_G1(*(RM.S), pairing);	
	element_random(param->P_0); //setup paramas and the secret key
	element_random(*(RM.mk));
	element_mul_zn(param->Q_0, param->P_0,  *(RM.mk));
	//in an additive group the null element is the identity, a + 0 = a
	element_set0(*(RM.S));
	RM.Q_tuple = init_Q_tuple(NULL, *(RM.mk), *param);
	return RM;
}
//check the rights
int check(public_key PK_u, attribute a) {
	//todo;
	return 1;
}


create_user_returntype create_user(master_key MK, public_key  PK_u, attribute a) {
	//firstly, check the rights to 'a'
		create_user_returntype ret; 
	if(check(PK_u, a))  {
		printf("there is no rights to this attribute: [ -- ]\n");
		return ret;
	}

	element_t mk_u;
	element_init_Zr(mk_u, pairing);
	element_from_hash(mk_u, (char*) PK_u.ID_tuple,
										sizeof(int) *	(PK_u.level + 1) / sizeof(char) );
	
	element_t SK_u;
	element_init_G1(SK_u, pairing);
	element_t temp,temp1,temp2;
	element_init_G1(temp1, pairing);
	element_init_G1(temp2, pairing);
	element_init_G1(temp, pairing);
	element_mul_zn(temp, PARAM.P_0, mk_u);
	//SK_u = mk_i * mk_u * P_0
	element_mul_zn(SK_u, temp, *(MK.mk));
	Q_tuple qtuple;
	qtuple.length = MK.Q_tuple.length - 1;
	qtuple.Q_tuple = (element_t* ) malloc(sizeof(element_t) * qtuple.length);
	int i;
	for(i = 0; i < qtuple.length; ++i) {
		element_init_same_as(qtuple.Q_tuple[i], MK.Q_tuple.Q_tuple[i]);
		element_set(qtuple.Q_tuple[i], MK.Q_tuple.Q_tuple[i]);
	}
		element_t P_a;
	element_t tempZ;
	element_init_Zr(tempZ, pairing);
	element_init_G1(P_a, pairing);
	H_4(&tempZ, *(MK.mk), a.name);
	element_mul_zn(P_a, PARAM.P_0 ,tempZ);
	element_t SK_ua;
	element_init_G1(SK_ua, pairing);
	element_mul_zn(temp2, P_a, mk_u);
	element_mul_zn(temp1, temp2, *(MK.mk));
	element_add(SK_ua, *(MK.S), temp1);
	//copy to ret
	ret.mk = (element_t* ) malloc(sizeof(element_t));
	ret.S = (element_t* ) malloc(sizeof(element_t));
	element_init_G1(*(ret.mk), pairing);
	element_init_G1(*(ret.S), pairing);
	element_set(*(ret.mk),SK_u );
	element_set(*(ret.S), SK_ua);
	ret.Q_tuple = qtuple;
//clear the temp vars.	
	element_clear(tempZ);
	element_clear(temp1);
	element_clear(temp);
	element_clear(temp2);
	element_clear(SK_u);
	element_clear(P_a);
	element_clear(SK_ua);
	element_clear(mk_u);
	return ret;
}

//return 1 - OK
//return 0 - FAIL
int add_CC(conjuctive_clouse* CC, attribute* attr) {
	int ret = 0;
	int i, len;
	public_key pk_cc;
	//check
	pk_cc = CC->attributes->DM;
	if (pk_cc.level != attr->DM.level) {
		return 0;
	}
	else {
		len = pk_cc.level;
	}
	for (i = 0; i < len; ++i) {
		if ((pk_cc.ID_tuple)[i] != (attr->DM.ID_tuple)[i]) {
			return 0;
		}
	}
	//add
	attribute* new = (attribute* ) malloc(sizeof(attribute) * (CC->length + 1) );
	for (i = 0; i < CC->length; i++) {
		new[i].name = CC->attributes[i].name;
		new[i].DM = CC->attributes[i].DM;
		//	element_init_same_as(new[i].SK_iua, CC->attributes[i].SK_iua);
		//	element_set(new[i].SK_iua, CC->attributes[i].SK_iua );
		//	element_clear(CC->attributes[i].SK_iua);
	}
	free(CC->attributes);
	CC->attributes = new;
	CC->length += 1;
	CC->attributes[CC->length].name = attr->name;
	CC->attributes[CC->length].DM  = attr->DM;
//	element_init_same_as(CC->attributes[CC->length].SK_iua, attr->SK_iua);
//	element_set(CC->attributes[CC->length].SK_iua, attr->SK_iua);
	return 1;
}

void init_attribute(attribute* attr, char* name, domain_manager* owner) {
	int i, len = strlen(name);
	attr->name = (char* ) malloc(sizeof(char) * len);
	strcpy(attr->name, name);
	attr->DM.level = (owner->pk).level + 1; 
	attr->DM.ID_tuple = (unsigned int* ) malloc(sizeof(unsigned int) * 
																							((owner->pk).level + 2)); 
	/* for(i = 0; i <= owner->pk.level; ++i) { */
	/* 	attr->DM.ID_tuple[i] = owner->pk.ID_tuple[i]; */
	/* } */
	for( i = 0; i <= (owner->pk).level; ++i ) {
		attr->DM.ID_tuple[i] = owner->pk.ID_tuple[i];
	}
	attr->DM.ID_tuple[i] = get_next_id(owner);
}


void init_conjuctive_clouse(conjuctive_clouse* CC, attribute* atts, int length) {
	CC->attributes = (attribute* ) malloc(sizeof(attribute)  * length);
	CC->length = length;
	int i;
	for (i = 0; i < length; ++i) {
		//name copy
		CC->attributes[i].name = (char* ) malloc(sizeof(char) * (strlen(atts[i].name + 1)));
		strcpy(CC->attributes[i].name, atts[i].name);
		//public_key copy
		int j;
		CC->attributes[i].DM.ID_tuple = (unsigned int* )
			malloc(sizeof(unsigned int) * (atts->DM.level + 1 ));
		CC->attributes[i].DM.level = atts->DM.level;
		for (j = 0; j <= atts->DM.level; ++j ) {
			CC->attributes[i].DM.ID_tuple[j] = atts->DM.ID_tuple[j];			
		}
	}
}


void free_attribute(attribute att) {
	free(att.name);
	free(att.DM.ID_tuple);
}

void free_conjuctive_clouse(conjuctive_clouse CC) {
	int i;
	for (i = 0; i < CC.length; ++i) {
		free_attribute(CC.attributes[i]);
	}
	free(CC.attributes);
}


void init_access_contorol_policy(access_control_policy* AC,
																 conjuctive_clouse* CC,
																 int length ) {
	AC->length = length;
	AC->CC = (conjuctive_clouse* ) malloc(sizeof(conjuctive_clouse) * length );
	int i;
	for (i = 0; i < length; ++i) {
		cc_copy(AC->CC + i, CC + i);
	}
}


void cc_copy (conjuctive_clouse* dest, conjuctive_clouse* src) {
	dest->length = src->length;
	dest->attributes = (attribute* ) malloc(sizeof(attribute) * dest->length);
	int i;
	for (i = 0; i < dest->length; ++i) {
		attribute_copy(dest->attributes + i, src->attributes + i);
	}
}

void attribute_copy (attribute* dest, attribute* src) {
	dest->name = (char* ) malloc(strlen(src->name) * sizeof(char));
	strcpy(dest->name, src->name);
	public_key_copy(&(dest->DM), &(src->DM));
}

void public_key_copy ( public_key* dest, public_key* src) {
  dest->level = src->level;
	dest->ID_tuple = (unsigned int* ) malloc(sizeof(unsigned int) *
																					 (dest->level + 1));
	int i;
	for (i = 0; i <= dest->level; ++i ) {
		dest->ID_tuple[i] = src->ID_tuple[i];
	}
}

void access_control_policy_copy(access_control_policy* dest,
																access_control_policy* src) {
	dest->length = src->length;
	dest->CC = (conjuctive_clouse* ) malloc(sizeof(conjuctive_clouse) * src->length);
	int i;
	for (i = 0; i < src->length; ++i) {
		cc_copy(dest->CC + i, src->CC + i);
	}
}

int check_ac(access_control_policy* ac, conjuctive_clouse* cc) {
	//todo
	return 1;
}

void add_AC(access_control_policy* ac, conjuctive_clouse* cc) {
	if( check_ac(ac,cc) ) {
		printf("[ add_ac function  FAIL ]\n");
	}
	conjuctive_clouse* temp = (conjuctive_clouse* ) malloc(
		sizeof(conjuctive_clouse) * (ac->length + 1));
	int i;
	for (i = 0; i < ac->length; ++i) {
		cc_copy(temp, ac->CC + i);
	}
	free_conjuctive_clouse(*(ac->CC));
	ac->length += 1;
	cc_copy(temp + ac->length - 1, cc);
	ac->CC = temp;
}

secret encrypt(access_control_policy AC, char* plain) {
	secret ret;
	element_t r;
	element_init_Zr(r, pairing);
	element_random(r);
	//set U_0
	element_t U_0;
	element_init_G1(U_0, pairing);
	ret.U_0 = (element_t* ) malloc(sizeof(element_t));
	element_init_G1(*(ret.U_0), pairing);
	element_mul_zn(U_0, PARAM.P_0, r);
	element_set(*(ret.U_0), U_0);
	//array
	int i, j;
	ret.N = AC.length;
	//space
	ret.n = (int* ) malloc(sizeof(int) * ret.N);
	ret.array = (element_t **) malloc(sizeof(element_t*) * ret.N );
	ret.secret = (char*) malloc(sizeof(char) * strlen(plain));
	for (i  = 0; i < AC.length; ++i) {
		ret.n[i] = AC.CC[i].length;
		ret.array[i] = (element_t* ) malloc(sizeof(element_t) * (1 + ret.n[i]));
	}
	//value
	for (i = 0; i < ret.N; ++i) {
		for (j = 0; j < ret.n[i]; ++j) {
			element_t temp;
			element_init_G1(temp, pairing);
			H_1(temp, AC.CC[i].attributes[j].DM.ID_tuple,
					(AC.CC[i].attributes[j].DM.level + 1) *
					sizeof(unsigned int) / sizeof(char) );
			element_mul_zn(ret.array[i][j], temp, r);
			element_clear(temp);
		}
		// sum of P_aij for j 
		element_t sum;
		element_init_G1(sum, pairing);
		ask_elementsum(&sum, AC.CC[i]);
		element_mul_zn(ret.array[i][ret.n[i]], sum, r);
		element_clear(sum);
	}
	int lcm = LCM(AC);
	char* xor;
	element_t P1; //H_1(PK_1)
	element_init_G1(P1, pairing);
	H_1(P1, AC.CC[0].attributes[0].DM.ID_tuple, 2 * sizeof(unsigned int) / sizeof(char));
	element_t temp, temp1;
	element_init_G1(temp, pairing);
	element_init_G1(temp1, pairing);
	element_mul_si(temp, P1, lcm);
	element_mul_zn(temp1, temp, r);
	element_clear(temp);
	element_init_GT(temp, pairing);
	element_pairing(temp, PARAM.Q_0, temp1);
	xor = H_2(temp);
	ret.secret = Xor(plain, xor);
	//clear all 
	element_clear(temp);
	element_clear(temp1);
	element_clear(P1);
	element_clear(U_0);
	element_clear(r);
	return ret;
}

void ask_elementsum(element_t* dest, conjuctive_clouse CC ) {
	//todo
}

int LCM(access_control_policy ac) {
	int ret;
	if (ac.length < 3 ) {
		if (ac.length == 0) {
			return 0;
		}
		else if (ac.length == 1){
			return ac.CC[0].length;
		}
		else {
			ret = ac.CC[0].length * ac.CC[1].length /gcd(ac.CC[0].length, ac.CC[1].length);
		}
	}
	else {
		int i, j, ret;
		ret = ac.CC[0].length * ac.CC[1].length /gcd(ac.CC[0].length, ac.CC[1].length);
		for (i = 2; i < ac.length; ++i ) {
			ret = ret * ac.CC[i].length / gcd(ac.CC[i].length, ret);
		}
	}
	return ret;
}

int gcd ( int a, int b ) {
  int c;
  while ( a != 0 ) {
     c = a; a = b%a;  b = c;
  }
  return b;
}

int 
gcdr ( int a, int b ) {
  if ( a==0 ) return b;
  return gcdr ( b%a, a );
}


char* Xor(char* a, char* b) {
	if (strlen(a) != strlen(b)) {
		return NULL;
	}
	char* ret = (char* ) malloc(sizeof(char) * ( 1 + strlen(a)));
	int i;
	for (i = 0; i < strlen(a); ++i) {
		ret[i] = a[i] + b[i];
	}
	ret[i] = '\0';
	return ret;
}

void param_copy_PP(params** dest, params* src) {
	params* temp = (params*) malloc(sizeof(params));
	element_init_same_as(temp->Q_0, src->Q_0);
	element_set(temp->Q_0, src->Q_0);
	element_init_same_as(temp->P_0, src->P_0);
	element_set(temp->Q_0, src->P_0);
	*dest = temp;
}

void param_copy(params* dest, params* src) {
	element_init_same_as(dest->Q_0, src->Q_0);
	element_set(dest->Q_0, src->Q_0);
	element_init_same_as(dest->P_0, src->P_0);
	element_set(dest->Q_0, src->P_0);
}
