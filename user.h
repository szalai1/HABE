#ifndef USER_H_INCLUDED
#define USER_H_INCLUDED

#include "crypto.h"

typedef struct public_key public_key;
typedef struct user_secret_key user_secret_key;
typedef struct user user;

struct user {
  char* name;
  public_key pk;
  params* param;
  
  user_secret_key* keys;
  int key_length;
};

// one of these structure belongs to one DM
struct user_secret_key {
	public_key pk; //DM
	Q_tuple Q_tuple;// Q-i + sk-a
	
	element_t* SK_a; // secret_key SK_u;
	attribute* attribute;
	int number_of_attributes;
};

void init_user(user*,public_key, char*);
void user_add_attribute( user* u, public_key att);
void free_user_secret_key( user_secret_key sk);
void user_secret_key_copy (user_secret_key* dest, user_secret_key* src);
char*  user_decrypt(user* u, secret* sec);
#endif
