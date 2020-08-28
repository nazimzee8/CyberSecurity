#include <stdio.h>
#include <stdlib.h>
#include <openssl/bn.h>

BIGNUM *privateKey(BIGNUM *p, BIGNUM *q, BIGNUM *e) {
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *phi = BN_new();
	BIGNUM *d = BN_new();
	BIGNUM *num = BN_new();
	BIGNUM *p_minus = BN_new();
	BIGNUM *q_minus = BN_new();

	BN_dec2bn(&num, "1");
	BN_sub(p_minus, p, num);
	BN_sub(q_minus, q, num);
	BN_mul(phi, p_minus, q_minus, ctx);
	BN_mod_inverse(d, e, phi, ctx);
	BN_CTX_free(ctx);
	return d;
}

BIGNUM *encrypt(BIGNUM *n, BIGNUM *e, BIGNUM *message) {
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *cipher = BN_new();
	BN_mod_exp(cipher, message, e, n, ctx);
	BN_CTX_free(ctx);
	return cipher;
}

BIGNUM *decrypt(BIGNUM *n, BIGNUM *d, BIGNUM *cipher) {
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *m = BN_new();
	BN_mod_exp(m, cipher, d, n, ctx);
	BN_CTX_free(ctx);
	return m;
}

BIGNUM *signature(BIGNUM *m, BIGNUM *d, BIGNUM *n) {
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *sig = BN_new();
	BN_mod_exp(sig, m, d, n, ctx);
	BN_CTX_free(ctx);
	return sig;
}

BIGNUM *verifySignature(BIGNUM *sig, BIGNUM *e, BIGNUM *n) {
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *m = BN_new();
	BN_mod_exp(m, sig, e, n, ctx);
	BN_CTX_free(ctx);
	return m;
}

BIGNUM *verifySignatureCA(BIGNUM *sigCA, BIGNUM *publicCA, BIGNUM *nCA) {
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *certCA = BN_new();
	BN_mod_exp(certCA, sigCA, publicCA, nCA, ctx);
	BN_CTX_free(ctx);
	return certCA;
}
