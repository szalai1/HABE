#include "domain_manager.h"
#include "user.h"
#include "communication.h"
#include <pbc.h>
#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>
#include <stdlib.h>
typedef struct domain_manager domain_manager;

void domain_manager_add_attribute(domain_manager* dm , char* name) {
	printf("[ domain_manager add \"%s\" attr ]\n", name);
	dm->number_of_attributes += 1;
	attribute* temp = (attribute* ) malloc(sizeof(attribute) * dm->number_of_attributes);
	int i;
	for (i = 0; i < dm->number_of_attributes - 1; ++i) {
		attribute_copy(temp + i, dm->attributes + i);
	}
	free(dm->attributes);
	dm->attributes = temp;
	init_attribute(dm->attributes + i, name, dm);
	printf("[ dom_manager_add DONE ]\n");
}

void init_domain_manager (domain_manager* dm, char* name) {
	printf("[ init_domain_managerg \"%s %p\" ]\n", name, dm);
//	dm->name
	char* x= (char* ) malloc(sizeof(char) * (strlen(name) + 1));
	dm -> name = x;
	strcpy(dm->name, name);
	dm->children_dm = NULL;
	dm->number_of_children = 0;

	dm->attributes = NULL;
	dm->number_of_attributes = 0;

	dm->users = NULL;
	dm->number_of_users = 0;
	dm->id = 0;
	DM_num++;
	printf("[ init \"%s\" %p domain manager DONE ]\n", dm->name, dm);


}
