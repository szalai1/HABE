#include "user.h"
#include "root.h"
#include "domain_manager.h"
#include "communication.h"
#include "crypto.h"
#include "hashs.h"
#include <pbc.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int DM_num;
domain_manager* dms;
root ROOT;
int user_num;
user* users;
pairing_t pairing;

////////////////////////////////////////////////////////////////////////////////
//test param and init_params fuctions
int test1() {
//	CHILDREN_NUM = 0;
	int i;
	public_key RM; // ID = {0}
	RM.ID_tuple = (unsigned int*) malloc(sizeof(int));
	RM.ID_tuple[0] = 0;
	RM.level = 0;
	public_key PK1 = init_public_key(&RM); //ID = {0,0}
	public_key PK2 = init_public_key(&RM); //ID = {0,1}
	public_key PK3 = init_public_key(&RM); //ID = {0,2}
	//next level this situation never happend in a real execution 
	//CHILDREN_NUM = 0;
	public_key pk1 = init_public_key(&PK1); // ID = {0,0,0}
	//CHILDREN_NUM = 0;
	public_key pk2 = init_public_key(&PK2); // ID = {0,1,,0}
	//
	//CHILDREN_NUM = 0;
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
//	CHILDREN_NUM = 0;
	return 0;
}

//Q_tuple test
//init param test
//SETUP test
void test2() {
	params param;
	master_key MK = SETUP(&param);
	printf("SETUP OK\n");
	int i = 0;
	for(i = 0; i < MK.Q_tuple.length; ++i) {
		element_printf("%B ", MK.Q_tuple.Q_tuple);
	}
	free_params(&param);
	
}

//create_DM test
//Q_tuple 'else' test
void test3() {
	int i;
	params param;
	public_key root_pk = init_public_key(NULL);
	master_key root_mk = SETUP(&param);
	public_key pk = init_public_key(&root_pk);
	//create_DM test
	master_key DM_mk = create_DM(root_mk, pk, param );
	for(i = 0; i < DM_mk.Q_tuple.length; ++i) {
		element_printf("%B XX \n", DM_mk.Q_tuple.Q_tuple);
	}

	free_public_key(&root_pk);
	element_printf(" cccccreat_DM : %d\t %B\n ASD\n",DM_mk.Q_tuple.length, DM_mk.Q_tuple.Q_tuple[1]);
	free_master_key(root_mk);
	element_printf(" cccccreat_DM : %d\t %B\n ASD\n",DM_mk.Q_tuple.length, DM_mk.Q_tuple.Q_tuple[1]);
	free_public_key(&pk);
	element_printf(" cccccreat_DM : %d\t %B\n ASD\n",DM_mk.Q_tuple.length, DM_mk.Q_tuple.Q_tuple[1]);
	free_master_key(DM_mk);

}

void test4() {
	set_up_comm();
	user* u1 = users;
	user* u2 = users  + 1;
	domain_manager* DM1 = dms;
	domain_manager* DM2 = dms + 1;
	domain_manager* DM3 = dms + 2;

	printf("%p", DM1);
	//root runs setup itsef
	create_root(&ROOT, "ROOT");
	init_domain_manager(DM1, "BME");
	init_domain_manager(DM2, "TTK");
	init_domain_manager(DM3, "VIK");
	printf("## I N I T   D O N E ##\n");
	set_up_domain_manager(DM1, ROOT.pk);
	set_up_domain_manager(DM2, DM1->pk);
	set_up_domain_manager(DM3, DM1->pk);

	domain_manager_add_attribute(DM1,  "A(ttribute)");
	domain_manager_add_attribute(DM2, "Betrum");
	domain_manager_add_attribute(DM2, "Cetrum");
	domain_manager_add_attribute(DM2, "Dettrum");
	domain_manager_add_attribute(DM3, "Etrum");
	domain_manager_add_attribute(DM3, "Fertum");

	init_user(u2, "Adam");
	init_user(u1, "Peter");

	
	
	
}

void printpk(public_key pk) {
	int i;
	printf("[ ");
	for(i = 0; i <= pk.level; ++i) {
		printf(" %d", pk.ID_tuple[i]);
	}
	printf(" ] \n");
}


int main() {


	
	printf("[ T E S T    S T A R T ]\n");
	test4();

	printf("\n[  T E S T    E N D    ]\n");

	return 0;
}
