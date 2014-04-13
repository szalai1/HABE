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

params PARAM;
unsigned int CHILDREN_NUM;
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
	element_t* mk;
	Q_tuple Q_tuple;
	element_t* S; 
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
	unsigned int length;
};


struct secret_user_keys {
Q_tuple Q_tuple;
element_t SK_a;
// secret_key SK_u;
 attribute attribute;
};


struct secret {
	unsigned int N;
	unsigned int* n;
	element_t** array;
	element_t* U_0;
	char* secret; //standard C string
};

#include "root.h"
#include "user.h"
#include "communication.h"
#include "domain_manager.h"

void init_params(params* param) ;
public_key init_public_key(public_key* parent);

public_key init_public_key(public_key* parent);

Q_tuple init_Q_tuple(Q_tuple* parent, element_t mk_i, params params);

void init_access_contorol_policy(access_control_policy* AC,
																 conjuctive_clouse* CC,
																 int length );
void init_conjuctive_clouse(conjuctive_clouse* CC, attribute* atts, int length);

void init_attribute(attribute* attr, char* name, domain_manager* owner);
void free_params(params* param);



void free_public_key(public_key* pk);


void free_public_key(public_key* pk);

void free_Q_tuple(Q_tuple tuple);

master_key create_DM(master_key MK, public_key p, params param);

void free_master_key(master_key mk);

master_key SETUP(params* param) ;

create_user_returntype create_user(master_key MK,public_key  PK_u, attribute a);
int add_CC(conjuctive_clouse* CC, attribute* attr);



char* Xor(char* plain, char* xor);

void param_copy_PP(params** dest, params* src);
void param_copy(params*, params*);
#endif

