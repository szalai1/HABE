#ifndef CRYPTO_H_INCLUDED
#define CRYPTO_H_INCLUDED

#include <pbc.h>




struct params;
typedef struct public_key public_key;
typedef struct params params;
typedef struct Q_tuple Q_tuple;
typedef struct master_key master_key;
typedef struct  secret_user_keys secret_user_keys;
typedef struct attribute attribute;
typedef master_key create_user_returntype;
typedef  struct conjuctive_clouse conjuctive_clouse;
typedef struct access_control_policy access_control_policy;
typedef struct secret secret;
typedef struct U U;
typedef struct part_of_U part_of_U;

typedef struct domain_manager domain_manager;

//level go from 0;
//the master_root is on the 0. level
struct public_key {
  unsigned int level;
  unsigned int* ID_tuple;
};

struct params{
  element_t P_0;
  element_t Q_0;
};

struct Q_tuple {
  element_t* Q_tuple;
  unsigned int length;
};

struct master_key {
  element_t* mk; // \in Z_q
  Q_tuple Q_tuple;
  element_t* S; // secret point $\in \mathbb{G}_1$
};

struct attribute{
  char* name; // standar C-string with '\0'
  // element_t SK_iua;
  public_key DM;
};

struct conjuctive_clouse {
  attribute* attributes;
  unsigned int length;
};

struct access_control_policy {
  conjuctive_clouse* CC;
  int length;
};

struct part_of_U {
  int length;
  element_t* array;
};

struct U {
  int length;
  part_of_U* array;
};

struct secret {
  int n_A;
  access_control_policy A;
  element_t U_0;
  U U;
  char* secret; //standard C string
};



#include "root.h"
#include "user.h"
#include "communication.h"
#include "domain_manager.h"

void init_params(params* param) ;

public_key init_public_key(public_key* parent);

Q_tuple init_Q_tuple(Q_tuple* parent, element_t mk_i, params params);

void init_access_contorol_policy(access_control_policy* AC,
																 conjuctive_clouse* CC,
																 int length );
void init_conjuctive_clouse(conjuctive_clouse* CC, attribute* atts, int length);

void init_attribute(attribute* attr, char* name, domain_manager* owner);
void free_params(params* param);



void free_public_key(public_key* pk);

void free_conjuctive_clouse(conjuctive_clouse CC);

void free_public_key(public_key* pk);

void free_Q_tuple(Q_tuple tuple);

void free_part_of_U(part_of_U* pou);

void free_U(U U);

void free_secret(secret* sec);

master_key create_DM(master_key MK, public_key p, params param);

void free_master_key(master_key mk);

void free_access_control_policy(access_control_policy* ac);

void access_control_policy_copy(access_control_policy* dest,
				access_control_policy* src);

master_key SETUP(params* param) ;

create_user_returntype create_user(master_key MK,public_key  PK_u, attribute a);
int add_CC(conjuctive_clouse* CC, attribute* attr);



char* Xor(char* plain, char* xor,int len);
void generate_SK_u (Q_tuple* ret, domain_manager* dm, public_key user );
void param_copy_PP(params** dest, params* src);
void param_copy(params*, params*);
void free_attribute(attribute att);
void Q_tuple_copy(Q_tuple* dest, Q_tuple* src);
void attribute_copy(attribute* dest, attribute* src);
void encrypt(secret* out,
	     user* user,
	     access_control_policy AC,
	     char* plain);
void fill_part_of_U(part_of_U* ,conjuctive_clouse,element_t*);
int LCM(access_control_policy ac);
unsigned char* decrypt(secret* sec, user_secret_key* sk);
int find(secret* sec, user_secret_key* sk) ;
#endif

