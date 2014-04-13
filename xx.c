//#include <pbc.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

char* Xor(char* a, char* b ) {
	if (strlen(a) != strlen(b)) {
		return NULL;
	}
	char* ret = (char* ) malloc(sizeof(char) * ( 1 + strlen(a)));
	int i;
	for (i = 0; i < strlen(a); ++i) {
		ret[i] = a[i] + b[i];
	}
	ret[i] = '\0';
	return ret;
}
int main() {
	char* c = foo("aaaa", "bbba");
	printf("[ %s ]\n", c);
	
}
