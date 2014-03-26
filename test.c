#include <stdio.h>
#include "crypto.h"
#include "hashs.h"
#include "pbc.h"
#include <stdlib.h>
#include <string.h>

//test param and init_params fuctions
int test1() {
	CHILDREN_NUM = 0;
	int i;
	public_key RM; // ID = {0}
	RM.ID_tuple = (unsigned int*) malloc(sizeof(int));
	RM.ID_tuple[0] = 0;
	RM.level = 0;
	public_key PK1 = init_public_key(&RM); //ID = {0,0}
	public_key PK2 = init_public_key(&RM); //ID = {0,1}
	public_key PK3 = init_public_key(&RM); //ID = {0,2}
	//next level this situation never happend in a real execution 
	CHILDREN_NUM = 0;
	public_key pk1 = init_public_key(&PK1); // ID = {0,0,0}
	CHILDREN_NUM = 0;
	public_key pk2 = init_public_key(&PK2); // ID = {0,1,,0}
	CHILDREN_NUM = 0;
	public_key pk3 = init_public_key(&PK3); // ID = {0,2,0}
	public_key pk4 = init_public_key(&PK3); // ID = {0,2,1}
	printf("\nTEST1\n");
	printf("\t it should be 0 2 1\n\t\t");
	for(i = 0; i <= pk4.level; ++i) {
		printf("%d ", pk4.ID_tuple[i]);
	}
	printf("\n");
	printf("\t it should be 0 2 0\n\t\t");
	for(i = 0; i <= pk3.level; ++i) {
		printf("%d ", pk3.ID_tuple[i]);
	}
	printf("\n");
	printf("\t it should be 0 0 0\n\t\t");
	for(i = 0; i <= pk1.level; ++i) {
		printf("%d ", pk1.ID_tuple[i]);
	}
	printf("\n");
	printf("\t it should be 0 2\n\t\t");
	for(i = 0; i <= PK3.level; ++i) {
		printf("%d ", PK3.ID_tuple[i]);
	}
	printf("\n");
	free_public_key(&RM);
	free_public_key(&PK1);
	free_public_key(&PK2);
	free_public_key(&PK3);
	free_public_key(&pk1);
	free_public_key(&pk2);
	free_public_key(&pk3);
	free_public_key(&pk4);
	CHILDREN_NUM = 0;
	return 0;
}

//Q_tuple test
//init param test
//SETUP test
void test2() {
	params param;
	element_t secret_key;
	master_key MK = SETUP(&param, &secret_key);
	printf("SETUP OK\n");
	int i = 0;
	for(i = 0; i < MK.Q_tuple.length; ++i) {
		element_printf("%B ", MK.Q_tuple.Q_tuple);
	}
	free_params(&param);
	element_clear(secret_key);
}

//create_DM test
//Q_tuple 'else' test
void test3() {
	params param;
	element_t secret_key;
	public_key root_pk = init_public_key(NULL);
	master_key root_mk = SETUP(&param, &secret_key);
	public_key pk = init_public_key(&root_pk);
	//create_DM test
	master_key DM_mk = create_DM(root_mk, )
	
	
}



int main() {
	char param[1024];
	size_t count = fread(param, 1, 1024, stdin);
	if (!count) pbc_die("input error");
	pairing_init_set_buf(pairing, param, count);

	
	printf("[ T E S T    S T A R T ]\n");
	test2();

	printf("[  T E S T    E N D    ]\n");

	return 0;
}
