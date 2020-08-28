#include "RSA1.h"
#include <stdio.h>
#include <stdlib.h>
#include <openssl/bn.h>

BIGNUM *privateKey(BIGNUM *p, BIGNUM *q, BIGNUM *e);
BIGNUM *encrypt(BIGNUM *n, BIGNUM *e, BIGNUM *message);
BIGNUM *decrypt(BIGNUM *n, BIGNUM *d, BIGNUM *cipher);
BIGNUM *signature(BIGNUM *m, BIGNUM *d, BIGNUM *n);
BIGNUM *verifySignature(BIGNUM *sig, BIGNUM *e, BIGNUM *n);
BIGNUM *verifySignatureCA(BIGNUM *sigCA, BIGNUM *publicCA, BIGNUM *nCA);

int main(void) {
	BIGNUM *p = BN_new(); 
	BIGNUM *q = BN_new(); 
	BIGNUM *e = BN_new(); 
	BIGNUM *n = BN_new();
	BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
	BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
	BN_hex2bn(&e, "0D88C3");
	BIGNUM *d = BN_new();
	d = privateKey(p, q, e);
	printf("%s", "The private key is: ");
	printf("%s\n", BN_bn2hex(d));

	BN_CTX *ctx = BN_CTX_new();
	BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5"); 
	//BN_mul(n, p, q, ctx);
	BN_hex2bn(&e, "01001");
	char* message = malloc(512 * sizeof(char));
	message = "4120746f702073656372657421";
	BIGNUM *m = BN_new();
	BN_hex2bn(&m, message);

	BIGNUM *cipher = BN_new();
	cipher = encrypt(n, e, m);
	printf("%s", "The cipher text is: ");
	printf("%s\n", BN_bn2hex(cipher));
	
	BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
	BN_hex2bn(&cipher, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");
	m = decrypt(n, d, cipher);
	printf("%s", "The decrypted message is: ");
	printf("%s\n", BN_bn2hex(m));

	message = "49206f776520796f752024323030302e";
	BIGNUM *sig = BN_new();
	BN_hex2bn(&m, message);
	sig = signature(m, d, n);
	printf("%s", "The first digital signature is: ");
	printf("%s\n", BN_bn2hex(sig));
	message = "49206f776520796f752024333030302e";
	BN_hex2bn(&m, message);
	sig = signature(m, d, n);
	printf("%s", "The second digital signature is: ");
	printf("%s\n", BN_bn2hex(sig));
	
	message = "4C61756E63682061206D697373696C652E";
	printf("%s", "The message's hex string is: ");
	printf("%s\n", message);
	BN_hex2bn(&sig, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
	BN_hex2bn(&e, "010001");
	BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
	m = verifySignature(sig, e, n);
	printf("%s", "The message verified is: ");
	printf("%s\n", BN_bn2hex(m));

	BIGNUM *sigCA = BN_new();
	BN_hex2bn(&sigCA,"737085EF4041A76A43D5789C7B5548E6BC6B9986BAFB0D038B78FE11F029A00CCD69140BC60478B2CEF007D5019DC4597A71FEF06E9EC1A0B0912D1FEA3D55C533050CCDC13518B06A68664CBF5621DA5BD948B98C3521915DDC75D77a462C2227A66FD33A17EBBEBD13C5122673C05DA335896AFB27D4DDAA74742E37E5013BA6D030B083D0A1C4752185B2E5FA670030A2BC53834DBFD6A883BBBCD6ED1CB31EF1580382008E9CEF90F21A5FA2A306DA5DBE9FDA5DA6E62FDE588018D3F1627BA6A39FAEA86972638165AE8283A3B5978A9B2051FF1A3F61401E48D06B38F9E1FA17D8774A88E63D36244FEF0AB99F70F38327F8CF2A057510AL8A0A8088CD");
	BIGNUM *certCA = BN_new();
	BN_hex2bn(&certCA, "2c2a46bf245dab54ddb47298621e9629309f0e2c90c4d80d535c7d4e8ab07d29");
	BIGNUM *publicCA = BN_new();
	BN_hex2bn(&publicCA, "010001");
	BIGNUM *nCA = BN_new();
	BN_hex2bn(&nCA, "DCAE58904DC1C4301590355B6E3C8215F52C5CBDE3DBFF7143FA642580D4EE18A24DF066D00A736E1198361764AF379DFDFA4184AFC7AF8CFE1A734DCF339790A2968753832BB9A675482D1D56377BDA31321AD7ACAB06F4AA5D4BB74746DD2A93C3902E798080EF13046A143BB59B92BEC207654EFCDAFCFF7AAEDC5C7E55310CE83907A4D7BE2FD30B6AD2B1DF5FFE5774533B3580DDAE8E4498B39F0ED3DAE0D7F46B29AB44A74B58846D924B81C3DA738B129748900445751ADD37319792E8CD540D3BE4C13F395E2EB8F35C7E108E8641008D456647B0A165CEA0AA29094EF397EBE82EAB0F72A7300EFAC7F4FD1477C3A45B2857C2B3F982FDB745589B");
	printf("%s", "The digital certificate is: ");
	printf("%s\n", BN_bn2hex(certCA));

	BIGNUM *verifiedSigCA = BN_new();
	verifiedSigCA = verifySignatureCA(sigCA, publicCA, nCA);
	printf("%s", "The certificate to be verified is: ");
	printf("%s\n", BN_bn2hex(verifiedSigCA));
	
	BN_free(p);
	BN_free(q);
	BN_free(e);
	BN_free(n);
	free(message);
	BN_CTX_free(ctx);
	BN_free(d);
	BN_free(cipher);
	BN_free(sig);
	BN_free(sigCA);
	BN_free(certCA);
	BN_free(publicCA);
	BN_free(nCA);
	BN_free(verifiedSigCA);
	
	return 0;
}


