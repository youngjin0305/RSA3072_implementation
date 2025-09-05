#include "rsa.h"

/**
 * RSA 암호화
 * ciphertext: 암호화된 결과를 저장할 Bignum 포인터
 * message: 암호화할 원문 Bignum
 * pub_key: 공개키
 */
void rsa_encrypt(Bignum* ciphertext, const Bignum* message, const RSA_PublicKey* pub_key) {
	bignum_mod_exp(ciphertext, message, &pub_key->e, &pub_key->n);
}

void rsa_decrypt(Bignum* message, const Bignum* ciphertext, const RSA_PrivateKey* priv_key) {
	Bignum m_p, m_q, h;

	// m_p = c^dP mod p
	bignum_mod_exp(&m_p, ciphertext, &priv_key->dP, &priv_key->p);
	// m_q = c^dQ mod q
	bignum_mod_exp(&m_p, ciphertext, &priv_key->dQ, &priv_key->q);

	// h = q^(-1) * (m_p - m_q) mod p
	if (bignum_compare(&m_p, &m_q) < 0) {
		bignum_add(&h, &m_p, &priv_key->p);
		bignum_subtract(&h, &h, &m_q);
	}
	else {
		bignum_subtract(&h, &m_p, &m_q);
	}

	Bignum temp;
	bignum_multiply(&temp, &h, &temp, &priv_key->p);
	bignum_divide(NULL, &h, &temp, &priv_key->p);

	bignum_multiply(&temp, &h, &priv_key->q);
	bignum_add(message, &m_q, &temp);


}