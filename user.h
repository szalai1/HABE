#ifndef USER_H_INCLUDED
#define USER_H_INCLUDED

#include "crypto.h"

//typedef struct public_key public_key;

typedef struct user user;

struct user {
	char* name;
	public_key pk;
	params* param;

	attribute* attributes;
	int number_of_attributes;
	
};


void init_user(user*, char*);

#endif
