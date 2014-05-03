#ifndef ROOT_H_INCLUDED
#define ROOT_H_INCLUDED


#include "domain_manager.h"
#include "communication.h"
#include "crypto.h"



typedef struct root root;
typedef struct domain_manager domain_manager;
struct root {
	public_key pk;
	master_key MK;
	char* name;
	params* param;
	public_key* DM;
	int number_of_dm;   
};

void create_root (root* root, char* name);

void free_root(root* root);

master_key root_creat_domian_manager(root*, public_key );

#endif 










