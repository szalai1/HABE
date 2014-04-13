#ifndef DOMAIN_MANAGER_H_INCLUDED
#define DOMAIN_MANAGER_H_INCLUDED

#include "crypto.h"

struct domain_manager {
	master_key MK;
	char* name;
	params* param;
	public_key pk;
	int id;
	public_key* children_dm;
	int number_of_children;

	public_key* attributes;
	int number_of_attributes;

	public_key* users;
	int number_of_users;
};

void domain_manager_add_attribute(domain_manager* dm , char* name);
void init_domain_manager (domain_manager* dm, char* name);
#endif
