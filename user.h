#ifndef USER_H_INCLUDED
#define USER_H_INCLUDED

#include "crypto.h"

typedef struct public_key public_key;
typedef struct secret_user_keys secret_user_keys;
typedef struct user user;

struct user {
	char* name;
	public_key pk;
	params* param;

	secret_user_keys key;
};

struct secret_user_keys {
Q_tuple Q_tuple;
element_t SK_a;
// secret_key SK_u;
attribute attribute;
};

void init_user(user*, char*);

#endif
