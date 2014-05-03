
#include <pbc.h>
#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>
#include "crypto.h"

#include "user.h"


void init_user( user* u, public_key dm, char* name) {
	u->name = (char* ) malloc(sizeof(char) * (strlen(name) + 1));
	strcpy(u->name, name) ;
	get_params(&(u->param));
	u->pk = init_public_key(&dm);
}

void user_add_attributes(user* u, public_key* atts, int len) {
	int i;
	for(i = 0; i < len; ++i) {
		user_add_attribute(u, atts[i]);
	}	
}

void user_add_attribute( user* u, public_key att) {
  user_secret_key temp;
  add_attribute(&temp, u->pk, att);
  int x = -1, i,j;
  for (i = 0; i < u->key_length; ++i ) {
    for (j = 0; j < u->keys[i].number_of_attributes; ++j) {
      if( pkcomp( u->keys[i].attribute[j].DM, att)) {
	return; //it s already added
      }
    }
    if( pkcomp(u->keys[i].pk, temp.pk)) {
      x = i;			
    }
  }
  //it s a new DM in the array
  if( x == -1) {
    user_secret_key* temp1 = (user_secret_key* ) malloc(
							sizeof(user_secret_key) * (u->key_length + 1)	);
    for (j = 0; j < u->key_length; ++j) {
      user_secret_key_copy(temp1 + j, u->keys + j);
      free_user_secret_key(u->keys[j]);
    }
    user_secret_key_copy(temp1 + j, &temp );
    free(u->keys);
    u->keys = temp1;
    u->key_length += 1;
  }
  else {
    // + SK_a and + attribute
    element_t* element_temp = (element_t* ) malloc( sizeof(element_t) *
						    ( u->keys[x].number_of_attributes + 1));
    attribute* attribute_temp = (attribute* ) malloc( sizeof(attribute) *
						      ( u->keys[x].number_of_attributes + 1));
    int k;
    // old copy 
    for (k = 0; k < u->keys[x].number_of_attributes; ++k) {
      element_init_G1(element_temp[k], pairing);
      element_set(element_temp[k], u->keys[x].SK_a[k]);
      element_clear(u->keys[x].SK_a[k]);
      attribute_temp[k] = u->keys[x].attribute[k];
    }
    // old free
    free(u->keys[x].attribute);
    free( u->keys[x].SK_a);
    //new copy
    element_init_G1(element_temp[k], pairing);
    element_set(element_temp[k], temp.SK_a[0]);
    attribute tempx;
    attribute_from_pk(&tempx, att);
    attribute_copy(attribute_temp + k, &tempx );
    free_attribute(tempx);
    u->keys[x].attribute = attribute_temp;
    u->keys[x].SK_a = element_temp;
    u->keys[x].number_of_attributes += 1;
  }
  free_user_secret_key(temp);
}

void free_user_secret_key( user_secret_key sk) {
  free_public_key(&(sk.pk));
  free_Q_tuple(sk.Q_tuple);
  int i;
  for (i = 0; i < sk.number_of_attributes; ++i) {
    element_clear(sk.SK_a[i]);
    free_attribute(sk.attribute[i]);
  }
  free(sk.SK_a);
  
}


void user_secret_key_copy (user_secret_key* dest, user_secret_key* src) {
  public_key_copy(&(dest->pk), &(src->pk) );
  Q_tuple_copy(&(dest->Q_tuple), &(src->Q_tuple) );
  int i;
  element_t* element_temp = (element_t* ) malloc( sizeof(element_t) *
						  ( src->number_of_attributes));
  attribute* attribute_temp = (attribute* ) malloc( sizeof(attribute) *
						    ( src->number_of_attributes));
  int k;
  
  for (k = 0; k < src->number_of_attributes; ++k) {
    element_init_G1(element_temp[k], pairing);
    element_set(element_temp[k], src->SK_a[k]);
    attribute_copy(attribute_temp + k, src->attribute + k);
  }
  dest->number_of_attributes = src->number_of_attributes;
  dest->attribute = attribute_temp;
  dest->SK_a = element_temp;
}

char* user_decrypt(user* u, secret* sec){
  //check 
  int x = right(u->keys, u->key_length, sec->A);
  if( x == -1) {
    return NULL;
  }
  char* ret; 
  ret = decrypt(sec, u->keys + x);
  char* fin = Xor(ret, sec->secret, MD5_DIGEST_LENGTH);
  printf("%s\n", fin);
  
  
}

int right(user_secret_key* keys, int length,  access_control_policy ac) {
  int i, j;
  for(i = 0; i < length; ++i ) {
    for( j = 0; j < ac.length; ++j) {
      if( good(keys + i, ac.CC + j)) {
	return i;
      }
    }
  }
  return -1;
}

int good(user_secret_key* sk, conjuctive_clouse* cc) {
  int i,j;
  for(i = 0; i < cc->length; ++i) {
    int flag = 0;
    for(j = 0; j < sk->number_of_attributes; ++j) {
      if(pkcomp(cc->attributes[i].DM, sk->attribute[j].DM)) {
	++flag;
      }
    }
    if( flag != 1) {
      return 0;
    }
  }
  return 1;
}
