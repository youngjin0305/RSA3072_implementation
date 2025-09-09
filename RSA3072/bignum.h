#ifndef BIGNUM_H
#define BIGNUM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---- 내부 표현 ----
// limbs[0]가 최하위 32비트(LE), size는 사용 중 limb 수(상위 0 limb는 제거)
typedef struct {
    uint32_t *limbs;
    size_t    size;
    size_t    capacity;
} Bignum;

// ---- 기본 관리 ----
void bignum_init(Bignum* bn);
void bignum_copy(Bignum* dest, const Bignum* src);
void bignum_free(Bignum* bn);

// ---- 16진수 <-> Bignum ----
int   bignum_from_hex(Bignum* bn, const char* hex_str); // 0 성공, <0 실패
char* bignum_to_hex(const Bignum* bn);                  // malloc 반환, free 필요

// ---- 비교 ----
// a > b -> 1, a < b -> -1, a == b -> 0
int bignum_compare(const Bignum* a, const Bignum* b);

// ---- 사칙연산(비부호 정수 전제) ----
void bignum_add(Bignum* result, const Bignum* a, const Bignum* b);
// a >= b를 가정(그 외에는 result=0으로 처리)
void bignum_subtract(Bignum* result, const Bignum* a, const Bignum* b);
void bignum_multiply(Bignum* result, const Bignum* a, const Bignum* b);
// quotient, remainder는 a/b, a%b
// b==0이면 quotient=remainder=0으로 처리
void bignum_divide(Bignum* quotient, Bignum* remainder, const Bignum* a, const Bignum* b);

// ---- 모듈러 거듭제곱: result = base^exp mod modulus ----
void bignum_mod_exp(Bignum* result, const Bignum* base, const Bignum* exp, const Bignum* modulus);

#ifdef __cplusplus
}
#endif
#endif // BIGNUM_H
