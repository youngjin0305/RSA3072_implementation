#include "rsa.h"

/**
 * RSA 암호화
 * ciphertext: 암호화된 결과를 저장할 Bignum 포인터
 * message: 암호화할 원문 Bignum
 * pub_key: 공개키
 */
void rsa_encrypt(Bignum* ciphertext, const Bignum* message, const RSA_PublicKey* pub_key) {

}

/**
 * RSA 복호화
 * message: 복호화된 결과를 저장할 Bignum 포인터
 * ciphertext: 복호화할 암호문 Bignum
 * priv_key: 개인키
 */
void rsa_decrypt(Bignum* message, const Bignum* ciphertext, const RSA_PrivateKey* priv_key) {

}