#ifndef HASHS_H_INCLUDED
#define HASHS_H_INCLUDED
typedef struct public_key public_key;
// H_1 : {0,1}* --> G_1
#define H_1(x,y,z) element_from_hash(x,y,z)
// H_3 ~ H_A: {0,1}* --> Z_q
#define H_3(x,y,z) element_from_hash(x,y,z)

unsigned char*  H_2(element_t);
void H_4(element_t* , element_t , char*);
void H_A(element_t* out, public_key pk);
void Hmki(element_t* out, public_key pk, element_t* key);
void H_pk_to_G1(element_t* out, public_key pk);

#endif
