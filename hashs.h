#ifndef HASHS_H_INCLUDED
#define HASHS_H_INCLUDED
// H_1 : {0,1}* --> G_1
#define H_1(x,y,z) element_from_hash(x,y,z)
// H_3 ~ H_A: {0,1}* --> Z_q
#define H_3(x,y,z) element_from_hash(x,y,z)

char*  H_2(element_t );
void H_4(element_t* , element_t , char*);

#endif
