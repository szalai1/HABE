#ifndef COMMUNICATION_H_INCLUDED
#define COMMUNICATION_H_INCLUDED

#include "domain_manager.h"
#include "hashs.h"
#include "crypto.h"
#include "root.h"
#include "user.h"
typedef struct user user;
typedef struct root root;
typedef struct domain_manager domain_manager;
extern int DM_num;
extern domain_manager* dms;
extern root ROOT;
extern int user_num;
extern user* users;
extern pairing_t pairing;

void set_up_comm();
void set_up_domain_manager(domain_manager* who, public_key parent);
void set_up_user(user* user, public_key parent_dm);
domain_manager* dm_from_publickey(public_key pk);
#endif
