#ifndef COMMUNICATION_H_INCLUDED
#define COMMUNICATION_H_INCLUDED

#include "domain_manager.h"
#include "hashs.h"
#include "crypto.h"
#include "root.h"
#include "user.h"

typedef struct attribute_db attribute_db; 
typedef struct user user;
typedef struct root root;
typedef struct domain_manager domain_manager;
typedef struct user_secret_key user_secret_key;

extern int DM_num;
extern domain_manager* dms;
extern root ROOT;
extern int user_num;
extern user* users;
extern pairing_t pairing;
extern attribute_db att;

struct attribute_db {
  attribute* attributes;
  int db;
};

void set_up_comm(int, int);
void set_up_domain_manager(domain_manager* who, public_key parent);
void set_up_user(user* user, public_key parent_dm);
domain_manager* dm_from_publickey(public_key pk);
void get_params(params** dest);
void add_attribute( user_secret_key* out, public_key pk, public_key att);

void ask_elementsum(element_t* dest, conjuctive_clouse cc);
void add_to_db(attribute_db*, attribute*);
#endif
