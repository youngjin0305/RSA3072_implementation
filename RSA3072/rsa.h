#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h> // uint32_t�� ���� ���� �ʺ� ������ ����ϱ� ����

// RSA Ű ��Ʈ ���� ���� (3072 ��Ʈ)
#define RSA_KEY_BITS 3072
// �Ҽ� p, q�� ��Ʈ ���� (Ű ������ ����)
#define RSA_PRIME_BITS (RSA_KEY_BITS / 2)
// ū �� ������ ���� �迭 ũ�� (32��Ʈ ���� ����)
#define BIGNUM_ARRAY_SIZE ((RSA_KEY_BITS / 32) + 1)
// �з�-��� �׽�Ʈ �ݺ� Ƚ�� (�ʿ��ϸ� �����ؼ� ���ּ���)
#define MILLER_RABIN_ROUNDS 40

typedef struct {
    uint32_t limbs[BIGNUM_ARRAY_SIZE];
    int size;
} Bignum; // ū ��


typedef struct {
    Bignum n; // Modulus
    Bignum e; // Public Exponent
} RSA_PublicKey; // ����Ű

typedef struct {
    Bignum n; // Modulus
    Bignum d; // Private Exponent
    // CRT�� ���� �ʿ��� ��
    Bignum p;
    Bignum q;
    Bignum dP; // d mod (p-1)
    Bignum dQ; // d mod (p-1)
    Bignum qInv; // q^(-1) mod p
} RSA_PrivateKey; // ����Ű


// =============================================================================
// ## 1. ū �� ���� ��� (���: �質��) ����: bignum.c
// =============================================================================

// Bignum �ʱ�ȭ, ����, ���� �Լ�
void bignum_init(Bignum* bn);
void bignum_copy(Bignum* dest, const Bignum* src);

// ���ڿ��� Bignum �� ��ȯ �Լ� (16���� ����)
int bignum_from_hex(Bignum* bn, const char* hex_str);
char* bignum_to_hex(const Bignum* bn);

// Bignum �� �Լ� (a > b -> 1, a < b -> -1, a == b -> 0)
int bignum_compare(const Bignum* a, const Bignum* b);

// �⺻ ��Ģ����
void bignum_add(Bignum* result, const Bignum* a, const Bignum* b);
void bignum_subtract(Bignum* result, const Bignum* a, const Bignum* b);
void bignum_multiply(Bignum* result, const Bignum* a, const Bignum* b);
void bignum_divide(Bignum* quotient, Bignum* remainder, const Bignum* a, const Bignum* b);

// ��ⷯ �ŵ����� (RSA�� �ٽ� ����)
// result = base^exp mod modulus
void bignum_mod_exp(Bignum* result, const Bignum* base, const Bignum* exp, const Bignum* modulus);


// =============================================================================
// ## 2. ������ ���� ������ (���: ������) ����: random.c
// =============================================================================

/**
 * ��ȣ�������� ������ ������ �����ϴ� �Լ�
 * buffer: ������ ������ ����
 * size: ������ ����Ʈ ��
 */
int generate_secure_random(unsigned char* buffer, size_t size);

// =============================================================================
// ## 3. �Ҽ� �Ǻ��� (���: �輺��) ����: prime.c
// =============================================================================

/**
 * �з�-��� �Ҽ� �Ǻ���
 * n: �Ǻ��� ū �� (�Ҽ� �ĺ�)
 * k: �׽�Ʈ �ݺ� Ƚ��
 * return �Ҽ��� Ȯ���� ������ 1, �ƴϸ� 0
 */
int is_probably_prime(const Bignum* n, int k);

// =============================================================================
// ## 4. �Ҽ� ���� ��� (���: �̳���) ����: prime.c
// =============================================================================

/**
 * ������ ��Ʈ ������ �Ҽ��� �����ϴ� �Լ�
 * prime: ������ �Ҽ��� ������ Bignum ������
 * bits: ���ϴ� �Ҽ��� ��Ʈ ���� (���� ������ 3072)
 */
void generate_prime(Bignum* prime, int bits);


// =============================================================================
// ## 5. �Ķ���� ��� (���: ��μ�) ����: rsa.c
// =============================================================================

/**
 * p�� q�κ��� RSA Ű ��(����Ű, ����Ű)�� ����
 * pub_key: ������ ����Ű�� ������ ����ü ������
 * priv_key: ������ ����Ű�� ������ ����ü ������
 */
void rsa_generate_keys(RSA_PublicKey* pub_key, RSA_PrivateKey* priv_key, const Bignum* p, const Bignum* q);

// =============================================================================
// ## 6. ��ȣȭ �� ��ȣȭ (���: �迵��) ����: rsa.c
// =============================================================================

/**
 * RSA ��ȣȭ
 * ciphertext: ��ȣȭ�� ����� ������ Bignum ������
 * message: ��ȣȭ�� ���� Bignum
 * pub_key: ����Ű
 */
void rsa_encrypt(Bignum* ciphertext, const Bignum* message, const RSA_PublicKey* pub_key);

/**
 * RSA ��ȣȭ
 * message: ��ȣȭ�� ����� ������ Bignum ������
 * ciphertext: ��ȣȭ�� ��ȣ�� Bignum
 * priv_key: ����Ű
 */
void rsa_decrypt(Bignum* message, const Bignum* ciphertext, const RSA_PrivateKey* priv_key);

// =============================================================================
// ## 7. 테스트 벡터 (담당: 김강민) 파일: main.c
// =============================================================================

/*
* 테스트 벡터 검증 -> main.c, 하단의 함수는 RSA-OAEP 패딩을 위한 구현체 
*/


// 원본 메시지를 OAEP 규칙에 맞게 패딩하여 암호화에 사용할 메시지 블록(EM)을 생성

// out: 패딩된 메시지(EM)를 저장할 버퍼
// msg: 원본 메시지
// msg_len: 원본 메시지 길이 (바이트)
// k: RSA 모듈러스 길이 (바이트)
// seed: OAEP에 사용될 시드(SHA256 해시 길이인 32바이트여야 함)

int rsa_oaep_pad(unsigned char* out, const unsigned char* msg, size_t msg_len, size_t k, const unsigned char* seed);