#include "root.h"
#include <openssl/md5.h>
#include "hashs.h"
#include <pbc.h>
#include <stdio.h>
#include <string.h>

void create_root (root* root, char* name) {
	printf("[ CREATE ROOT ... ]\n");
	root->pk = init_public_key(NULL);
	root->name = (char* ) malloc( sizeof(char) *(1 + strlen(name)));
	strcpy(root->name, name);
	root->param = (params* ) malloc(sizeof(params));
	root->DM = NULL;
	root->number_of_dm = 0;
	root->MK = SETUP(root->param);
	printf("[ ROOT DONE ] \n");
}

void free_root (root* root) {
	free(root->name);
	free_params(root->param);
	free(root->param);
	free_master_key(root->MK);
}

master_key root_create_domain_manager (root* root, public_key pk_of_dm) {
 master_key  return_val = create_DM(root->MK, pk_of_dm, *(root->param));
	return return_val;
}



































