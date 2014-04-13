#ifndef ACCESS
#define ACCESS

#include <pbc.h>
#include <stdio.h>
#include <string.h>
#include "crypto.h"

struct conjuctive_clause {
attribute* attributes;
int length;
};

struct access_policy {
	conjuctive_clause* CC;
	int length;
};




#endif
