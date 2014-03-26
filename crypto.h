#ifndef CRYPTO_H_INCLUDED
#define CRYOPTO_H_INCLUDED

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

struct Q_tuple {
	element_t* Q_tuple;
	unsigned int length;
};

struct master_key {
	element_t* mk;
	Q_tuple Q_tuple;
	element_t* S; 
  };  

void init_params(params* param) ;

void free_params(params* param);

public_key init_public_key(public_key* parent);

void free_public_key(public_key* pk);

public_key init_public_key(public_key* parent);

void free_public_key(public_key* pk);

Q_tuple init_Q_tuple(Q_tuple* parent, element_t mk_i, params params);

void free_Q_tuple(Q_tuple tuple);

master_key create_DM(master_key MK, public_key p, params param);

void free_master_key(master_key mk);

master_key SETUP(params* param, element_t* secret_key) ;

#endif
