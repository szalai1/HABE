#include <pbc.h>
#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>
#include "hashs.h"
#include "crypto.h"
/*
         O
       /   \
     DM_1   LM_DM
     / | \
    /  A0 \ 
   O       O
  / | \     | \ 
 A1 A2 O    U  A3
  
*/
pairing_t pairing;


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
  element_printf("init q tuple \n \tP_0 :  %B \n\t mk_i: %B \n", params.P_0, mk_i);
  //in case of RM
  if (parent == NULL ) {
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
    element_init_same_as(ret.Q_tuple[i], Q);
    element_set(ret.Q_tuple[i], Q);
  }
  element_clear(Q);
  return ret;
}

void free_Q_tuple(Q_tuple tuple) {
  if(tuple.Q_tuple == NULL) { return;}
  int i;
  for(i = 0; i < tuple.length; ++i) {
    element_clear(tuple.Q_tuple[i]);
  }
  free(tuple.Q_tuple);	
}




//MALLOC ALERT! use free master_key
//MK is masterkey of parent DM
//INPUT: parent master_key: MK 
//RETUNR new DM master keys
//p is public key of child
master_key create_DM(master_key MK, public_key p, params param) {
  //element_printf("MASTER KEY: mk:%B\n S: %B \n", *(MK.mk), *(MK.S));
  //init masterkey of the child DM
  master_key ret;
  element_t temp, temp1;
  // element_init_G1(temp, pairing);
  ret.mk = (element_t* ) malloc(sizeof(element_t));
  ret.S = (element_t *) malloc(sizeof(element_t));
  element_init_same_as(*(ret.mk), *(MK.mk));
  element_init_same_as(*(ret.S),*(MK.S));
   element_random(*(ret.mk));
  ret.Q_tuple = init_Q_tuple(&(MK.Q_tuple), *(ret.mk), param);
  // S_i+1 = S_i + mk_i * H_1( PK_i+1)
	//element_from_hash needs char*, so i had to do a trick
  H_pk_to_G1(&temp, p);
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
  element_random(param->P_0);//setup paramas and the secret key
  element_random(*(RM.mk));
  element_mul_zn(param->Q_0, param->P_0,  *(RM.mk));
  element_printf("SETUP Q0 %B \n %B\n%B\n", param->Q_0, param->P_0, RM.mk[0]);
  //in an additive group the null element is the identity, a + 0 = a
  element_set0(*(RM.S));
  RM.Q_tuple = init_Q_tuple(NULL, *(RM.mk), *param);
  element_printf("SETUP RM.Qtup %B param%B\n", RM.Q_tuple.Q_tuple[0], param->Q_0);
  return RM;
}
//check the rights
int check(public_key PK_u, attribute a) {
	//todo;
	return 1;
}


/* create_user_returntype create_user(master_key MK, public_key  PK_u, attribute a) { */
/* 	//firstly, check the rights to 'a' */
/* 		create_user_returntype ret;  */
/* 	if(check(PK_u, a))  { */
/* 		printf("there is no rights to this attribute: [ -- ]\n"); */
/* 		return ret; */
/* 	} */

/* 	element_t mk_u; */
/* 	element_init_Zr(mk_u, pairing); */
/* 	element_from_hash(mk_u, (char*) PK_u.ID_tuple, */
/* 										sizeof(int) *	(PK_u.level + 1) / sizeof(char) ); */
	
/* 	element_t SK_u; */
/* 	element_init_G1(SK_u, pairing); */
/* 	element_t temp,temp1,temp2; */
/* 	element_init_G1(temp1, pairing); */
/* 	element_init_G1(temp2, pairing); */
/* 	element_init_G1(temp, pairing); */
/* 	element_mul_zn(temp, PARAM.P_0, mk_u); */
/* 	//SK_u = mk_i * mk_u * P_0 */
/* 	element_mul_zn(SK_u, temp, *(MK.mk)); */
/* 	Q_tuple qtuple; */
/* 	qtuple.length = MK.Q_tuple.length - 1; */
/* 	qtuple.Q_tuple = (element_t* ) malloc(sizeof(element_t) * qtuple.length); */
/* 	int i; */
/* 	for(i = 0; i < qtuple.length; ++i) { */
/* 		element_init_same_as(qtuple.Q_tuple[i], MK.Q_tuple.Q_tuple[i]); */
/* 		element_set(qtuple.Q_tuple[i], MK.Q_tuple.Q_tuple[i]); */
/* 	} //i ll buy you a beer if you read this . szalaipeti.vagyok@gmail.com */
/* 		element_t P_a; */
/* 	element_t tempZ; */
/* 	element_init_Zr(tempZ, pairing); */
/* 	element_init_G1(P_a, pairing); */
/* 	H_4(&tempZ, *(MK.mk), a.name); */
/* 	element_mul_zn(P_a, PARAM.P_0 ,tempZ); */
/* 	element_t SK_ua; */
/* 	element_init_G1(SK_ua, pairing); */
/* 	element_mul_zn(temp2, P_a, mk_u); */
/* 	element_mul_zn(temp1, temp2, *(MK.mk)); */
/* 	element_add(SK_ua, *(MK.S), temp1); */
/* 	//copy to ret */
/* 	ret.mk = (element_t* ) malloc(sizeof(element_t)); */
/* 	ret.S = (element_t* ) malloc(sizeof(element_t)); */
/* 	element_init_G1(*(ret.mk), pairing); */
/* 	element_init_G1(*(ret.S), pairing); */
/* 	element_set(*(ret.mk),SK_u ); */
/* 	element_set(*(ret.S), SK_ua); */
/* 	ret.Q_tuple = qtuple; */
/* //clear the temp vars.	 */
/* 	element_clear(tempZ); */
/* 	element_clear(temp1); */
/* 	element_clear(temp); */
/* 	element_clear(temp2); */
/* 	element_clear(SK_u); */
/* 	element_clear(P_a); */
/* 	element_clear(SK_ua); */
/* 	element_clear(mk_u); */
/* 	return ret; */
/* } */

//return skiu public function it can be computed by ~everybody
void generate_SK_u (Q_tuple* ret, domain_manager* dm, public_key user ) {
  //check
  ret->Q_tuple = (element_t* ) malloc(sizeof(element_t) * (dm->MK.Q_tuple.length) );
  int i, j;//copy Qi -1 -et 
  for (i = 0; i < dm->MK.Q_tuple.length - 1; ++i) {
    element_init_same_as(ret->Q_tuple[i], dm->MK.Q_tuple.Q_tuple[i]);
    element_set(ret->Q_tuple[i], dm->MK.Q_tuple.Q_tuple[i]);
  }
  element_t temp, temp1, temp2;
  element_init_G1(temp2,pairing);
  element_init_G1(temp1, pairing);
  element_init_Zr(temp, pairing);
  // H_3(temp, user.ID_tuple, (user.level + 1) * sizeof(unsigned int)/sizeof(char));
  H_A(&temp, user);
  element_mul_zn(temp1, dm->param->P_0, temp);
  element_mul_zn(temp2, temp1, dm->MK.mk);//!!!!!!!!!!
  element_init_G1(ret->Q_tuple[i], pairing);
  element_set(ret->Q_tuple[i], temp2);
  element_clear(temp);
  element_clear(temp1);
  element_clear(temp2);
  ret->length = dm->MK.Q_tuple.length;
  //return SKiu
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
	  attribute_copy(new + i, CC->attributes + i);
	  free_attribute(CC->attributes[i]);
	}
	free(CC->attributes);
	attribute_copy(new + i, attr);
	CC->attributes =  new;
	CC->length += 1;
        
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
	attr->DM.ID_tuple[i] = get_next_id(& (owner->pk)) ;
}


void init_conjuctive_clouse(conjuctive_clouse* CC, attribute* atts, int length) {
  int i;
  for( i = 1; i < length; ++i) {
    public_key temp1;
    temp1.level = atts[i-1].DM.level - 1;
    temp1.ID_tuple = atts[i-1].DM.ID_tuple;
    public_key temp2;
    temp2.level = atts[i].DM.level - 1;
    temp2.ID_tuple = atts[i].DM.ID_tuple;
    if(!pkcomp(temp1, temp2)) {
      printf("@@@@@@@ INIT  CC  FAIL @@@@@@@@@\n");
      exit(EXIT_FAILURE); 
      return;
    }
  }
  
  CC->attributes = (attribute* ) malloc(sizeof(attribute)  * length);
  CC->length = length;
  for (i = 0; i < length; ++i) {
    attribute_copy(CC->attributes + i, atts + i);
  }
}



void free_attribute(attribute att) {
	free(att.name);
	free(att.DM.ID_tuple);
}

void free_conjuctive_clouse(conjuctive_clouse CC) {
  if(CC.attributes == NULL) { return; }
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



void public_key_copy ( public_key* dest, public_key* src) {
  dest->level = src->level;
  dest->ID_tuple = (unsigned int* ) malloc(sizeof(unsigned int) *
					   (dest->level + 1));
  int i;
  for (i = 0; i <= dest->level; ++i ) {
    dest->ID_tuple[i] = src->ID_tuple[i];
  }
}

int check_ac(access_control_policy* ac, conjuctive_clouse* cc) {
  //todo
  return 0;
} 

void add_AC(access_control_policy* ac, conjuctive_clouse* cc) {
  if( check_ac(ac,cc) ) {
    printf("[ add_ac function  FAIL ]\n");
  }
  conjuctive_clouse* temp = (conjuctive_clouse* ) malloc(
							 sizeof(conjuctive_clouse) * (ac->length + 1));
  int i;
  for (i = 0; i < ac->length; ++i) {
    cc_copy(temp + i, ac->CC + i);
    free_conjuctive_clouse(ac->CC[i]);
  }
  ac->length += 1;
  cc_copy(temp + i, cc);
  free(ac->CC);
  ac->CC = temp;
}

void encrypt(secret* out,
	     user* user,
	     access_control_policy AC,
	     char* plain) {
  element_t r;
  element_init_Zr(r, pairing);
  element_random(r);
  //set U_0
  element_init_G1(out->U_0, pairing);
  element_mul_zn(out->U_0, user->param->P_0, r);
  //element_printf(" encrypt r Po%B\n", out->U_0);
  // U
  out->U.array = (part_of_U* ) malloc(sizeof(part_of_U) * ( AC.length));
  out->U.length = AC.length;
  int i;
  for ( i = 0; i < AC.length; ++i) {
    fill_part_of_U(out->U.array + i,AC.CC[i], &r);
  }
  //secret
  int n_A = LCM(AC);
  out->n_A = n_A;
  element_t P_1, temp1, temp2;
  public_key DM1;
  DM1.level = 1;
  DM1.ID_tuple = user->pk.ID_tuple;
  H_pk_to_G1(&P_1, DM1 );
  //element_printf("p-1: %B  \n", P_1 );
  element_init_G1(temp1, pairing);
  element_mul_s(temp1, P_1, n_A);
  element_init_G1(temp2, pairing);
  element_mul_zn(temp2, temp1, r);	
  element_t e;
  element_init_GT(e,pairing);
  element_pairing(e, user->param->Q_0, temp2);
  element_printf("#######nencrypt e%B\n", e);
  unsigned char* key = H_2(e);
  out->secret = Xor(key, plain, MD5_DIGEST_LENGTH);
  access_control_policy_copy(&(out->A), &AC);
  element_clear(r);
  element_clear(e);
}

void fill_part_of_U(part_of_U* part, conjuctive_clouse cc, element_t* e) {
  part->length = cc.attributes[0].DM.level - 1;
  part->array = (element_t* ) malloc(sizeof(element_t) * part->length);
  int i;
  public_key temp;
  temp.ID_tuple = cc.attributes[0].DM.ID_tuple;
  for( i = 0; i < part->length - 1; ++i) {
    temp.level = i + 2;
    element_init_G1(part->array[i], pairing);
    element_t out;
    H_pk_to_G1(&out, temp);
    element_mul_zn(part->array[i], out, *e);
    element_clear(out);
  }
  element_t tmp;
  ask_elementsum(&tmp, cc);
  //  element_printf("sum = %B\n", tmp);
  //element_printf("R = %B\n", *e);
  element_init_G1(part->array[i], pairing);
  element_mul_zn(part->array[i], tmp, *e);
  element_printf("tmp  %B \n r * sum %B \n", tmp, part->array[i]);
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
    int i, j;
    ret = ac.CC[0].length * ac.CC[1].length /gcd(ac.CC[0].length, ac.CC[1].length);
    for (i = 2; i < ac.length; ++i ) {
      ret = ret * ac.CC[i].length / gcd(ac.CC[i].length, ret);
    }
  }
  return ret;
}
//from stackoverflow
int gcd ( int a, int b ) {
  int c;
  while ( a != 0 ) {
    c = a; a = b%a;  b = c;
  }
  return b;
}

int gcdr ( int a, int b ) {
  if ( a==0 ) return b;
  return gcdr ( b%a, a );
}


char* Xor(char* a, char* b, int len) {
  char* ret = (char* ) malloc(sizeof(char) * ( 1 + len ));
  int i;
  for (i = 0; i < len; ++i) {
    ret[i] = a[i] ^ b[i];
  }
  ret[i] = '\0';
  return ret;
}

void param_copy_PP(params** dest, params* src) {
  params* temp = (params*) malloc(sizeof(params));
  element_init_same_as(temp->Q_0, src->Q_0);
  element_set(temp->Q_0, src->Q_0);
  element_init_same_as(temp->P_0, src->P_0);
  element_set(temp->P_0, src->P_0);
  //element_printf("DDDD %B\n", temp->P_0);
  *dest = temp;
}

void param_copy(params* dest, params* src) {  
  element_init_same_as(dest->Q_0, src->Q_0);
  element_set(dest->Q_0, src->Q_0);
  element_init_same_as(dest->P_0, src->P_0);
  element_set(dest->Q_0, src->P_0);
}

void attribute_copy(attribute* dest, attribute* src) {
	dest->name = (char*) malloc(sizeof(char) * strlen(src->name));
	strcpy(dest->name, src->name);
	public_key_copy(&(dest->DM), &(src->DM));
}


void Q_tuple_copy(Q_tuple* dest, Q_tuple* src) {
	int i;
	dest->Q_tuple = (element_t* ) malloc(sizeof(element_t) *
																			 (src->length));
	for( i = 0; i < src->length; ++i) {
		element_init_G1(dest->Q_tuple[i], pairing);
		element_set(dest->Q_tuple[i], src->Q_tuple[i]);
	}
	dest->length = src->length;
}

void generate_SK_ua (element_t* ret,
		     domain_manager* dm,
		     public_key user,
		     public_key att) { 
  // element_printf("SK_ua %B\n", dm->MK.mk[0]);
  element_t mku, mka, temp2, temp3, temp4;
  element_init_G1(*ret, pairing);
  element_init_Zr(mka, pairing);
  element_init_G1(temp2, pairing);
  element_init_G1(temp3, pairing);
  element_init_G1(temp4, pairing);	
  Hmki(mka, att, dm->MK.mk);
  // element_printf("\tSKua mka %B\n", mka);
  //element_printf("gen SK_ua %B\n mka %B\n dmMKS: %B \n", dm->MK.mk[0], mka, dm->MK.S[0]);
  H_A(&mku, user);//mku = H_A(ID_A)
  // element_printf("\t\nittt\n%B\n\n",mku);
  element_mul_zn(temp2, dm->param->P_0, mka); //P_a = P_0 * mk_u
  element_mul_zn(temp3, temp2, mku); //P_a*mku
  element_mul_zn(temp4, temp3, *(dm->MK.mk));
  // element_printf("\n%B\n", *(dm->MK.S));
  element_add(*ret, *(dm->MK.S), temp4);
  element_printf("\n ret %B\n", ret[0]);
  element_clear(mku);
  element_clear(temp2);
  element_clear(temp3);
  element_clear(temp4);
  element_clear(mka);
} 

void access_control_policy_copy(access_control_policy* dest,
				access_control_policy* src) {
  dest->length = src->length;
  dest->CC = (conjuctive_clouse* ) malloc(sizeof(conjuctive_clouse) * dest->length);
  int i;
  for( i = 0; i < dest->length; ++i) {
    cc_copy(dest->CC + i, src->CC + i);
  }
}

void free_secret(secret* sec) {
  free_access_control_policy(&(sec->A));
  element_clear(sec->U_0);
  free_U(sec->U);
  free(sec->secret);  
}

void free_U(U U) {
  int i;
  for(i = 0; i < U.length; ++i) {
    free_part_of_U(U.array + i);
  }
  free(U.array);
}

void free_part_of_U(part_of_U* pou) {
  int i;
  for( i = 0; i < pou->length; ++i ) {
    element_clear(pou->array[i]);
  }
  free(pou->array);
}

void free_access_control_policy(access_control_policy* ac) {
  int i;
  for( i = 0; i < ac-> length; ++i ) {
    free_conjuctive_clouse(ac->CC[i]);
  }
  free(ac->CC);
}

unsigned char* decrypt(secret* sec, user_secret_key* sk ) {
  //counter
  int flag = 0;
  int temp; //= sec->n_A / sk->number_of_attributes;
  element_t sum;
  element_init_G1(sum, pairing);
  element_set0(sum);
  int i,j, x = find(sec, sk);
  conjuctive_clouse* cc = sec->A.CC + x;
  temp = sec->n_A / cc->length;
  for( i = 0; i < sk->number_of_attributes; ++i ) {
    for(j = 0; j < cc->length; ++j) {
      if(pkcomp(sk->attribute[i].DM, cc->attributes[j].DM)) {
	element_add(sum, sum, sk->SK_a[i]);
      }
    }
  }
  element_t temp1, ctr;
  element_init_GT(ctr, pairing);
  element_init_G1(temp1, pairing);
  element_mul_s(temp1, sum, temp);
  element_pairing(ctr, sec->U_0, temp1);
  //divisor
  element_t prod, tmp1, mul,tmp;
  element_init_G1(tmp, pairing);
  element_init_G1(mul, pairing);
  element_init_GT(tmp1, pairing);
  element_set0(tmp1);
  element_init_GT(prod, pairing);
  element_set1(prod);
  //last is sum
  int len1 = sec->U.array[x].length - 1;
  element_mul_s(tmp, sec->U.array[x].array[len1], temp);
  //last is mki*mku*P0
  int len2  = sk->Q_tuple.length - 1;
  element_pairing(tmp1, tmp, sk->Q_tuple.Q_tuple[len2]);

  for( i = 0; i < len1; ++i) {
    element_t elo, y, L; 
     element_init_G1(L, pairing);

    element_init_G1(elo, pairing);
    element_init_GT(y, pairing);
    element_mul_s(elo, sk->Q_tuple.Q_tuple[i + 1], 
		   sec->n_A);

    element_pairing(y, sec->U.array[x].array[i], elo);
    element_mul(prod, prod, y);
    element_clear(elo);
    element_clear(y);
  }
  element_mul(tmp1, tmp1, prod);
  element_t end;
  element_init_GT(end, pairing);
  element_div(end, ctr, tmp1);
  //compute the H_2 hash
  unsigned char* ret = H_2(end);
  element_printf("\n  ######### \ndecrypt  %B \n", end );
  return ret;
}


int find(secret* sec, user_secret_key* sk) {
  int i;
  for( i = 0; i < sec->A.length; ++i) {
    public_key pk;
    pk.ID_tuple = sec->A.CC[i].attributes[0].DM.ID_tuple;
    pk.level = sec->A.CC[i].attributes[0].DM.level - 1;
    if( pkcomp(pk, sk->pk) ) {
      return  i;
    }
  }
  printf("@@@@@@@@@@@@@ I L Y E N   N I N C S @@@@@@@@@@@@@\n");
}


void element_mul_s(element_t a, element_t b, int n) {
  int i;
  element_init_same_as(a, b);
  element_set0(a);
  for(i = 0; i < n; ++i) {
    element_add(a, a, b);
  }
}
