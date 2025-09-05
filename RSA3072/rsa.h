#pragma once
#ifndef RSA_H
#define RSA_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h> // uint32_t와 같은 고정 너비 정수를 사용하기 위함

// RSA 키 비트 길이 정의 (3072 비트)
#define RSA_KEY_BITS 3072
// 소수 p, q의 비트 길이 (키 길이의 절반)
#define RSA_PRIME_BITS (RSA_KEY_BITS / 2)
// 큰 수 저장을 위한 배열 크기 (32비트 정수 기준)
#define BIGNUM_ARRAY_SIZE ((RSA_KEY_BITS / 32) + 1)
// 밀러-라빈 테스트 반복 횟수 (필요하면 수정해서 써주세요)
#define MILLER_RABIN_ROUNDS 40

typedef struct {
    uint32_t limbs[BIGNUM_ARRAY_SIZE];
    int size;
} Bignum; // 큰 수


typedef struct {
    Bignum n; // Modulus
    Bignum e; // Public Exponent
} RSA_PublicKey; // 공개키

typedef struct {
    Bignum n; // Modulus
    Bignum d; // Private Exponent
    // CRT를 위해 필요한 값
    Bignum p;
    Bignum q;
    Bignum dP; // d mod (p-1)
    Bignum dQ; // d mod (p-1)
    Bignum qInv; // q^(-1) mod p
} RSA_PrivateKey; // 개인키


// =============================================================================
// ## 1. 큰 수 연산 모듈 (담당: 김나현) 파일: bignum.c
// =============================================================================

// Bignum 초기화, 복사, 해제 함수
void bignum_init(Bignum* bn);
void bignum_copy(Bignum* dest, const Bignum* src);

// 문자열과 Bignum 간 변환 함수 (16진수 권장)
int bignum_from_hex(Bignum* bn, const char* hex_str);
char* bignum_to_hex(const Bignum* bn);

// Bignum 비교 함수 (a > b -> 1, a < b -> -1, a == b -> 0)
int bignum_compare(const Bignum* a, const Bignum* b);

// 기본 사칙연산
void bignum_add(Bignum* result, const Bignum* a, const Bignum* b);
void bignum_subtract(Bignum* result, const Bignum* a, const Bignum* b);
void bignum_multiply(Bignum* result, const Bignum* a, const Bignum* b);
void bignum_divide(Bignum* quotient, Bignum* remainder, const Bignum* a, const Bignum* b);

// 모듈러 거듭제곱 (RSA의 핵심 연산)
// result = base^exp mod modulus
void bignum_mod_exp(Bignum* result, const Bignum* base, const Bignum* exp, const Bignum* modulus);


// =============================================================================
// ## 2. 안전한 난수 생성기 (담당: 정태진) 파일: random.c
// =============================================================================

/**
 * 암호학적으로 안전한 난수를 생성하는 함수
 * buffer: 난수를 저장할 버퍼
 * size: 생성할 바이트 수
 */
int generate_secure_random(unsigned char* buffer, size_t size);

// =============================================================================
// ## 3. 소수 판별법 (담당: 김성우) 파일: prime.c
// =============================================================================

/**
 * 밀러-라빈 소수 판별법
 * n: 판별할 큰 수 (소수 후보)
 * k: 테스트 반복 횟수
 * return 소수일 확률이 높으면 1, 아니면 0
 */
int is_probably_prime(const Bignum* n, int k);

// =============================================================================
// ## 4. 소수 생성 모듈 (담당: 이나원) 파일: prime.c
// =============================================================================

/**
 * 지정된 비트 길이의 소수를 생성하는 함수
 * prime: 생성된 소수를 저장할 Bignum 포인터
 * bits: 원하는 소수의 비트 길이 (지금 과제는 3072)
 */
void generate_prime(Bignum* prime, int bits);


// =============================================================================
// ## 5. 파라미터 계산 (담당: 김민수) 파일: rsa.c
// =============================================================================

/**
 * p와 q로부터 RSA 키 쌍(공개키, 개인키)을 생성
 * pub_key: 생성된 공개키를 저장할 구조체 포인터
 * priv_key: 생성된 개인키를 저장할 구조체 포인터
 */
void rsa_generate_keys(RSA_PublicKey* pub_key, RSA_PrivateKey* priv_key, const Bignum* p, const Bignum* q);

// =============================================================================
// ## 6. 암호화 및 복호화 (담당: 김영진) 파일: rsa.c
// =============================================================================

/**
 * RSA 암호화
 * ciphertext: 암호화된 결과를 저장할 Bignum 포인터
 * message: 암호화할 원문 Bignum
 * pub_key: 공개키
 */
void rsa_encrypt(Bignum* ciphertext, const Bignum* message, const RSA_PublicKey* pub_key);

/**
 * RSA 복호화
 * message: 복호화된 결과를 저장할 Bignum 포인터
 * ciphertext: 복호화할 암호문 Bignum
 * priv_key: 개인키
 */
void rsa_decrypt(Bignum* message, const Bignum* ciphertext, const RSA_PrivateKey* priv_key);

// =============================================================================
// ## 7. 테스트 벡터 (담당: 김강민) 파일: main.c
// =============================================================================

/*
* 테스트 벡터 검증
* 일단 int로 선언 했는데 원하는 방식 있으시면 바꾸셔도 됩니다.
* int로 한건 return으로 success flag를 반환해서 모든 테스트 벡터를 통과했는지 확인하는 용도를 생각했어요
* 필요하면 제가 AES할 때 만들었던 코드 보여드릴게요
* 파라미터는 테스트 벡터가 어떻게 있는지를 확인을 안해보고 만든거라 그냥 원하는대로 수정해서 사용해주세요
*/
int check_test_vector(const char* file_name);

#endif // RSA_H