#include "rsa.h"

/**
 * RSA ��ȣȭ
 * ciphertext: ��ȣȭ�� ����� ������ Bignum ������
 * message: ��ȣȭ�� ���� Bignum
 * pub_key: ����Ű
 */
void rsa_encrypt(Bignum* ciphertext, const Bignum* message, const RSA_PublicKey* pub_key) {

}

/**
 * RSA ��ȣȭ
 * message: ��ȣȭ�� ����� ������ Bignum ������
 * ciphertext: ��ȣȭ�� ��ȣ�� Bignum
 * priv_key: ����Ű
 */
void rsa_decrypt(Bignum* message, const Bignum* ciphertext, const RSA_PrivateKey* priv_key) {

}