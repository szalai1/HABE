#include "user.h"
#include "root.h"
#include "domain_manager.h"
#include "communication.h"
#include "crypto.h"
#include "hashs.h"
#include <pbc.h>
#include <openssl/md5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int DM_num;
domain_manager* dms;
root ROOT;
int user_num;
user* users;
pairing_t pairing;
attribute_db att;


void printpk(public_key pk) {
  int i;
  printf("[ ");
  for(i = 0; i <= pk.level; ++i) {
  printf(" %d", pk.ID_tuple[i]);
}
printf(" ] \n");
}

void printhash(unsigned char* s) {
  int i;
  printf("[ len:%d ", MD5_DIGEST_LENGTH - 1);
  for (i = 0; i < MD5_DIGEST_LENGTH - 1; i++){
    printf ("%02x", s[i]);
  }
  printf(" ] \n");
  printf("[ len:%d ", MD5_DIGEST_LENGTH);
  for (i = 0; i < MD5_DIGEST_LENGTH; i++){
    printf ("%02x", s[i]);
  }
  printf(" ] \n");
  printf("[ len:%d ", MD5_DIGEST_LENGTH + 1);
  for (i = 0; i < MD5_DIGEST_LENGTH + 1; i++){
    printf ("%02x", s[i]);
  }
  printf(" ] \n");
}
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
  set_up_comm(3,2);
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
  
  attribute atts[5];
  attribute_copy(atts, DM1->attributes);// A
  attribute_copy(atts + 1, DM2->attributes);//B
  attribute_copy(atts + 2, DM2->attributes + 1);//C
  attribute_copy(atts + 3, DM3->attributes);//D
  attribute_copy(atts + 4, DM3->attributes + 1);//E
  init_user(u2, DM2->pk, "Adam");
  init_user(u1, DM2->pk, "Peter");
  
  user_add_attribute(u1, atts->DM);
  user_add_attribute(u1, atts[1].DM);
  user_add_attribute(u1, atts[2].DM);
  user_add_attribute(u1, atts[3].DM);
  user_add_attribute(u2, atts[3].DM);
  
}


void test5() {
//hash tests
  set_up_comm(3,2);
  public_key A;
  public_key B;
  int a[] = {1, 2, 3 ,4};
  A.ID_tuple = a;
  A.level = 3;
  int b[] = {1, 2, 3, 4, 5};
  B.ID_tuple = b;
  B.level = 4;
  element_t x;
  H_A(&x, A);
  printpk(A);
  element_printf("A:\n %B\n",x);
  element_clear(x);
  H_A(&x, B);
  printpk(B);
  element_printf("B:\n %B\n",x);
  element_clear(x);
  B.level -= 1;
  H_A(&x, B);
  printpk(B);
  element_printf("A~B:\n %B\n",x);
  element_clear(x);
  H_A(&x, A);
  printpk(A);
  element_printf("A:\n %B\n",x);
  element_clear(x);	
}

void test6() {
  set_up_comm(3,2);
  public_key A;
  public_key B;
  int a[] = {1, 2, 3 ,4};
  A.ID_tuple = a;
  A.level = 3;
  int b[] = {2, 2, 3, 4, 5};
  B.ID_tuple = b;
  B.level = 4;
  element_t key;
  element_init_G1(key,pairing);
  element_random(key);
  element_t x;
  Hmki(&x, A, &key);
  printpk(A);
  element_printf("A:\nkey:\n %B \n%B\n",key, x);
  element_clear(x);
  Hmki(&x, B, &key);
  printpk(B);
  element_printf("B:\nkey:\n %B \n%B\n",key , x);
  element_clear(x);
  B.level -= 1;
  Hmki(&x, B, &key);
  printpk(B);
  element_printf("A~B:\nkey:\n %B \n%B\n",key, x);
  element_clear(x);
  Hmki(&x, A, &key);
  printpk(A);
  element_printf("A:\nkey:\n %B \n%B\n",key,x);
  element_clear(x);
}

void test7() {
 
  set_up_comm(3,2);
 
  element_t g; 
  element_t n, sum;
  element_init_G1(g, pairing);
  element_init_G1(n, pairing);
  element_init_G1(sum, pairing);
  element_set0(n);
  
  element_random(g); 
  element_add(sum, g, n);
  unsigned char * s = H_2(g); 
  printhash(s); 
  free(s);
  
  element_random(g);  
  s = H_2(g); 
  printhash(s);
  s = H_2(sum); 
  printhash(s);
  free(s);

}

void test8() {
  set_up_comm(3,2);
  element_t a;
  public_key pk;
  pk.ID_tuple = (unsigned int*) malloc(sizeof(unsigned int) * 5);
  pk.level = 4;
  int i;
  for(i = 0; i < pk.level; ++i ) {
    pk.ID_tuple[i] = i * 13 % 7;
  }
  H_pk_to_G1(&a, pk);
  element_printf(" %B \n", a);
  pk.level = 3;
  H_pk_to_G1(&a, pk);
  element_printf(" %B \n", a);
  pk.level = 3;
}
//AC test
//lcm test
void test9() {
  set_up_comm(3,2);
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
  
  conjuctive_clouse elso;
  init_conjuctive_clouse(&elso, att.attributes, 1);
  conjuctive_clouse masodik;
  init_conjuctive_clouse(&masodik, att.attributes + 1, 3);
  conjuctive_clouse harmadik;
  init_conjuctive_clouse(&harmadik, att.attributes + 4, 1);
  add_CC(&harmadik, att.attributes + 5);
  
  access_control_policy ac;
  ac.length = 0;
  ac.CC = NULL;
  add_AC(&ac, &elso);
  add_AC(&ac, &masodik);
  add_AC(&ac, &harmadik);
  
  printf("%d\n", LCM(ac));
}

void test10() {
  char a[] = "halihalihali";
  char b[] = "asdasdasdasd";
  char* temp = Xor(a, b, 12);
  printf("#%s#\n", temp);
  char* temp2 = Xor(temp, a, 12);
  printf("#%s#\n", temp2);
  free(temp);
  free(temp2);
}


void test11() {
  set_up_comm(4, 2);
  user* u1 = users;
  user* u2 = users  + 1;
  domain_manager* DM1 = dms;
  domain_manager* DM2 = dms + 1;
  domain_manager* DM3 = dms + 2;
  domain_manager* DM4 = dms + 3;
  
  printf("%p", DM1);
  //root runs setup itsef
  create_root(&ROOT, "ROOT");
  init_domain_manager(DM1, "BME");
  init_domain_manager(DM2, "TTK");
  init_domain_manager(DM3, "VIK");
  init_domain_manager(DM4, "alebratanszek");


  set_up_domain_manager(DM1, ROOT.pk);
  set_up_domain_manager(DM2, DM1->pk);
  set_up_domain_manager(DM3, DM1->pk);
  set_up_domain_manager(DM4, DM2->pk);
  
  domain_manager_add_attribute(DM1,  "A");
   domain_manager_add_attribute(DM2, "B");
   domain_manager_add_attribute(DM2, "C");
   domain_manager_add_attribute(DM2, "D");
  domain_manager_add_attribute(DM3, "E");
  domain_manager_add_attribute(DM4, "F");
  
  attribute atts[6];
  attribute_copy(atts, DM1->attributes);// A
  
  attribute_copy(atts + 1, DM2->attributes);//B 
  attribute_copy(atts + 2, DM2->attributes + 1);//C 
  attribute_copy(atts + 3, DM2->attributes + 2);//D 
  
  attribute_copy(atts + 4, DM3->attributes);//E 
  attribute_copy(atts + 5, DM4->attributes);//f 
  
   init_user(u2, DM2->pk, "Adam");
   init_user(u1, DM4->pk, "Peter");
   
   //  user_add_attribute(u1, atts->DM);
   user_add_attribute(u1, atts[5].DM);
   // user_add_attribute(u1, atts[2].DM); 
   // user_add_attribute(u1, atts[3].DM); 
   // user_add_attribute(u2, atts[3].DM); 
   
    conjuctive_clouse elso;
   init_conjuctive_clouse(&elso, atts, 1);
   conjuctive_clouse masodik;
   init_conjuctive_clouse(&masodik, atts + 1, 2);
     conjuctive_clouse harmadik;
   init_conjuctive_clouse(&harmadik, atts + 5, 1);
   add_CC(&harmadik, att.attributes + 5);
   //  element_printf("p-1xxxxx: %B  \n", DM1->MK.S[0] );
   access_control_policy ac;
   ac.length = 0;
   ac.CC = NULL;
   add_AC(&ac, &elso);
   
   add_AC(&ac, &masodik);
  add_AC(&ac, &harmadik);
	
  unsigned char key[16] = "keykeykeykeykeyk";
  secret sk;

  encrypt(&sk, u2, ac, key );
  user_decrypt(u1, &sk);
  int i;
  element_printf("%B\n", ROOT.MK.S[0]);
  return;
  
  
}

void testx() {
  set_up_comm(3,2);
  element_t a,b,c,d;
  element_init_G1(a,pairing);
  element_init_G1(b,pairing);
  element_init_G1(c,pairing);
  element_random(a);
  element_random(b);
  element_printf("%B\n%B\nXXXXXXX\n", a,b);
  element_add(a,a,b);
  element_printf("%B\n%B\b", a,b);
}


int main() {
  
  
	
  printf("[ T E S T    S T A R T ]\n");
  printf("%d\n\n", MD5_DIGEST_LENGTH);
  test11();

  printf("\n[  T E S T    E N D    ]\n");
  
  return 0;
}
