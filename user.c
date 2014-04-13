#include <pbc.h>
#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>
#include "crypto.h"

#include "user.h"


void init_user( user* u, char* name) {
	u->name = (char* ) malloc(sizeof(char) *
														(strlen(name) + 1));
	strcpy(u->name, name) ;
}
