#include "pbc.h"

pairing_t pairing;

void setup() {
	char param[1024];
	size_t count = fread(param, 1, 1024, stdin);
	if (!count) pbc_die("input error");
	pairing_init_set_buf(pairing, param, count);
}


int main(void){



element_t g, h;
element_t public_key, secret_key;
element_t sig;
element_t temp1, temp2;

element_init_G2(g, pairing);
element_init_G2(public_key, pairing);
element_init_G1(h, pairing);
element_init_G1(sig, pairing);
element_init_GT(temp1, pairing);
element_init_GT(temp2, pairing);
element_init_Zr(secret_key, pairing);
element_random(g);

element_random(secret_key);


element_pow_zn(public_key, g, secret_key);

element_from_hash(h, "ABCDEF", 6);

element_pow_zn(sig, h, secret_key);

pairing_apply(temp1, sig, g, pairing);
pairing_apply(temp2, h, public_key, pairing);
if (!element_cmp(temp1, temp2)) {
    printf("signature verifies\n");
} else {
    printf("signature does not verify\n");
}

return 0;
}

