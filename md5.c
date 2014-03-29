#include <openssl/md5.h>
#include <stdio.h>
#include <string.h>

int main(){
	unsigned char hash[MD5_DIGEST_LENGTH];
	
	const char msg[] = "ezt kell1 sdfgsdgfdfgdfgdgsdfgdgdgsdgsdgshashelni";

	int i = 0;
	MD5((unsigned char*)&msg, strlen(msg), (unsigned char*)&hash);
//	MD5_CTX ctx;
//	MD5_Init(&ctx);
//	MD5_Update(&ctx, msg, strlen(msg));
//	MD5_Final(hash, &ctx);
//	hash[17] = '\0';

	char mdstirng[33];
	for(i = 0; i < 16; ++i) {
		sprintf(&mdstirng[i*2], "%02x", (unsigned int) hash[i]);
		//	printf("%s\n",hash);
	}

	
	printf("%s\n",mdstirng);
	return 0;
}
