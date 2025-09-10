#include "rsa.h"
#include <string.h>
#include <ctype.h>
#include<stdbool.h>

/* ---- 내부 상수/헬퍼 ---- */
#define LIMB_BITS 32u
#define MAX_LIMBS BIGNUM_ARRAY_SIZE

static inline void bn_normalize(Bignum* a) {
    int s = (a->size < 0) ? 0 : a->size;
    if (s > MAX_LIMBS) s = MAX_LIMBS;
    while (s > 0 && a->limbs[s - 1] == 0) s--;
    a->size = s;
}
static inline void bn_zero(Bignum* a) {
    memset(a->limbs, 0, sizeof(a->limbs));
    a->size = 0;
}
static inline int bn_is_zero(const Bignum* a) { return a->size == 0; }
static inline int bn_is_odd(const Bignum* a) { return (a->size > 0) && (a->limbs[0] & 1u); }
static inline int bn_ucmp(const Bignum* a, const Bignum* b) { // unsigned compare
    if (a->size != b->size) return (a->size > b->size) ? 1 : -1;
    for (int i = a->size - 1; i >= 0; --i) {
        if (a->limbs[i] != b->limbs[i]) return (a->limbs[i] > b->limbs[i]) ? 1 : -1;
    }
    return 0;
}
static inline uint32_t u32_min(uint32_t a, uint32_t b) { return a < b ? a : b; }

// 비트 길이 
static int bn_bit_length(const Bignum* a) {
    if (a->size == 0) return 0;
    uint32_t ms = a->limbs[a->size - 1];
    int bits = (a->size - 1) * (int)LIMB_BITS;
    int leading = 32;
    while (leading > 0 && ((ms >> (leading - 1)) & 1u) == 0u) leading--;
    return bits + leading;
}
// i번째 비트(0=LSB) 조회 
static int bn_get_bit(const Bignum* a, int bit_index) {
    if (bit_index < 0) return 0;
    int limb = bit_index / (int)LIMB_BITS;
    int off = bit_index % (int)LIMB_BITS;
    if (limb >= a->size) return 0;
    return (int)((a->limbs[limb] >> off) & 1u);
}
// q의 i번째 비트를 1로 set (0→1) 
static void bn_set_bit(Bignum* a, int bit_index) {
    int limb = bit_index / (int)LIMB_BITS;
    int off = bit_index % (int)LIMB_BITS;
    if (limb >= MAX_LIMBS) return; // 초과분 무시
    a->limbs[limb] |= (1u << off);
    if (a->size <= limb) a->size = limb + 1;
}
// 1비트 왼쪽 시프트 (a <<= 1)
static void bn_shl1(Bignum* a) {
    uint32_t carry = 0;
    for (int i = 0; i < a->size; ++i) {
        uint64_t v = ((uint64_t)a->limbs[i] << 1) | carry;
        a->limbs[i] = (uint32_t)v;
        carry = (uint32_t)(v >> 32);
    }
    if (carry && a->size < MAX_LIMBS) {
        a->limbs[a->size++] = carry;
    }
}
// 1비트 오른쪽 시프트 (a >>= 1) 
static void bn_shr1(Bignum* a) {
    uint32_t carry = 0;
    for (int i = a->size - 1; i >= 0; --i) {
        uint32_t new_carry = a->limbs[i] & 1u;
        a->limbs[i] = (a->limbs[i] >> 1) | (carry << 31);
        carry = new_carry;
        if (i == 0) break;
    }
    bn_normalize(a);
}
// r = a + b, carry 반환 
static uint32_t bn_uadd(Bignum* r, const Bignum* a, const Bignum* b) {
    uint64_t carry = 0;
    int n = (a->size > b->size) ? a->size : b->size;
    if (n > MAX_LIMBS) n = MAX_LIMBS;
    for (int i = 0; i < n; ++i) {
        uint64_t av = (i < a->size) ? a->limbs[i] : 0;
        uint64_t bv = (i < b->size) ? b->limbs[i] : 0;
        uint64_t s = av + bv + carry;
        r->limbs[i] = (uint32_t)s;
        carry = s >> 32;
    }
    r->size = n;
    if (carry && r->size < MAX_LIMBS) {
        r->limbs[r->size++] = (uint32_t)carry;
        carry = 0;
    }
    return (uint32_t)carry;
}
// r = a - b (a>=b 가정), borrow 반환(0 정상, 1 underflow) 
static uint32_t bn_usub(Bignum* r, const Bignum* a, const Bignum* b) {
    if (bn_ucmp(a, b) < 0) { // underflow
        bn_zero(r);
        return 1;
    }
    uint64_t borrow = 0;
    int n = a->size;
    for (int i = 0; i < n; ++i) {
        uint64_t av = a->limbs[i];
        uint64_t bv = (i < b->size) ? b->limbs[i] : 0;
        uint64_t d = av - bv - borrow;
        r->limbs[i] = (uint32_t)d;
        borrow = (d >> 63) & 1u; // 음수면 borrow=1
    }
    r->size = n;
    bn_normalize(r);
    return (uint32_t)borrow;
}
// r += small(0..2^32-1) 
static void bn_add_small(Bignum* r, uint32_t x) {
    uint64_t carry = x;
    int i = 0;
    while (carry != 0 && i < MAX_LIMBS) {
        uint64_t v = (uint64_t)r->limbs[i] + carry;
        r->limbs[i] = (uint32_t)v;
        carry = v >> 32;
        i++;
    }
    if (i > r->size) r->size = i;
    if (carry && r->size < MAX_LIMBS) {
        r->limbs[r->size++] = (uint32_t)carry;
    }
}
// r *= small(0..2^32-1) 
static void bn_mul_small(Bignum* r, uint32_t k) {
    if (k == 0 || bn_is_zero(r)) { bn_zero(r); return; }
    uint64_t carry = 0;
    for (int i = 0; i < r->size; ++i) {
        uint64_t v = (uint64_t)r->limbs[i] * k + carry;
        r->limbs[i] = (uint32_t)v;
        carry = v >> 32;
    }
    if (carry && r->size < MAX_LIMBS) {
        r->limbs[r->size++] = (uint32_t)carry;
    }
}

// r = (a + b) mod m, 가정: a<m, b<m
static void bn_mod_add(Bignum* r, const Bignum* a, const Bignum* b, const Bignum* m) {
    Bignum t; bn_zero(&t);
    bn_uadd(&t, a, b); // t = a + b
    // t < 2m 이므로 한 번만 감산 검사
    if (bn_ucmp(&t, m) >= 0) {
        bn_usub(&t, &t, m);
    }
    *r = t;
}
// r = (2a) mod m, 가정: a<m 
static void bn_mod_double(Bignum* r, const Bignum* a, const Bignum* m) {
    Bignum t; bn_zero(&t);
    uint32_t carry = 0;
    int n = a->size;
    for (int i = 0; i < n; ++i) {
        uint64_t v = ((uint64_t)a->limbs[i] << 1) | carry;
        t.limbs[i] = (uint32_t)v;
        carry = (uint32_t)(v >> 32);
    }
    t.size = n;
    if (carry && t.size < MAX_LIMBS) t.limbs[t.size++] = carry;
    if (bn_ucmp(&t, m) >= 0) bn_usub(&t, &t, m);
    *r = t;
}

static void bn_mod(Bignum* a, const Bignum* m) {
    if (bn_is_zero(m) || bn_is_zero(a)) return;
    if (bn_ucmp(a, m) < 0) return;

    Bignum q, r;
    bignum_divide(&q, &r, a, m);  // 긴 나눗셈으로 바로 나머지
    *a = r;
}

/* ====== Public API ====== */

void bignum_init(Bignum* bn) { bn_zero(bn); }

void bignum_copy(Bignum* dest, const Bignum* src) {
    if (dest == src) return;
    memcpy(dest->limbs, src->limbs, sizeof(uint32_t) * MAX_LIMBS);
    dest->size = src->size;
}

// hex → bignum (대소문자/0x 허용). 성공 0, 실패 -1
int bignum_from_hex(Bignum* bn, const char* hex_str) {
    bn_zero(bn);
    if (!hex_str) return -1;

    // 앞쪽 공백/0x/0X 스킵
    const char* p = hex_str;
    while (*p && isspace((unsigned char)*p)) p++;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;

    int seen = 0;
    for (; *p; ++p) {
        if (isspace((unsigned char)*p)) continue;
        int v;
        if (*p >= '0' && *p <= '9') v = *p - '0';
        else if (*p >= 'a' && *p <= 'f') v = 10 + (*p - 'a');
        else if (*p >= 'A' && *p <= 'F') v = 10 + (*p - 'A');
        else return -1; // invalid
        // bn = bn*16 + v
        bn_mul_small(bn, 16u);
        bn_add_small(bn, (uint32_t)v);
        seen = 1;
    }
    if (!seen) { bn_zero(bn); return 0; }
    bn_normalize(bn);
    return 0;
}

// bignum → hex (소문자, 선행 0 제거), 호출자가 free() 필요 
char* bignum_to_hex(const Bignum* bn) {
    if (bn->size == 0) {
        char* s = (char*)malloc(2);
        if (s) { s[0] = '0'; s[1] = '\0'; }
        return s;
    }
    // 최악 길이: size*8 + 1
    size_t maxlen = (size_t)bn->size * 8u + 1u;
    char* buf = (char*)malloc(maxlen);
    if (!buf) return NULL;

    // 최상위 limb는 선행 0 제거, 이후 limb는 8자리로 채움
    int i = bn->size - 1;
    int n = snprintf(buf, maxlen, "%x", bn->limbs[i]);
    for (i = bn->size - 2; i >= 0; --i) {
        n += snprintf(buf + n, maxlen - n, "%08x", bn->limbs[i]);
    }
    return buf;
}

// 비교: a>b → 1, a<b → -1, a==b → 0
int bignum_compare(const Bignum* a, const Bignum* b) {
    return bn_ucmp(a, b);
}

// result = a + b 
void bignum_add(Bignum* result, const Bignum* a, const Bignum* b) {
    bn_zero(result);
    bn_uadd(result, a, b);
    bn_normalize(result);
}

// result = a - b (a<b이면 0으로 클리어) 
void bignum_subtract(Bignum* result, const Bignum* a, const Bignum* b) {
    bn_zero(result);
    if (bn_ucmp(a, b) < 0) { bn_zero(result); return; }
    bn_usub(result, a, b);
}

void bignum_split(const Bignum* a, Bignum* high, Bignum* low, int m) {
    bignum_init(high);
    bignum_init(low);

    // 하위 부분 복사
    low->size = (a->size < m) ? a->size : m;
    memcpy(low->limbs, a->limbs, low->size * sizeof(uint32_t));
    bn_normalize(low);

    // 상위 부분 복사
    if (a->size > m) {
        high->size = a->size - m;
        memcpy(high->limbs, &a->limbs[m], high->size * sizeof(uint32_t));
        bn_normalize(high);
    }
}

// 왼쪽으로 n limb 만큼 쉬프트 (base^n 곱)
void bignum_shift_left(Bignum* result, const Bignum* a, int n) {
    bignum_init(result);
    if (a->size == 0 || n < 0) return;
    if (a->size + n > MAX_LIMBS) { // 오버플로우 처리
        // 필요에 따라 에러 처리 (여기선 무시)
        return;
    }
    memmove(&result->limbs[n], a->limbs, a->size * sizeof(uint32_t));
    result->size = a->size + n;
}

void bignum_multiply_schoolbook(Bignum* result, const Bignum* a, const Bignum* b) {
    bignum_init(result);
    if (a->size == 0 || b->size == 0) return;

    for (int i = 0; i < a->size; ++i) {
        uint64_t carry = 0;
        for (int j = 0; j < b->size; ++j) {
            int k = i + j;
            if (k >= MAX_LIMBS) break;
            uint64_t sum = (uint64_t)result->limbs[k]
                + (uint64_t)a->limbs[i] * (uint64_t)b->limbs[j]
                + carry;
            result->limbs[k] = (uint32_t)sum;
            carry = sum >> 32;
        }
        int k = i + b->size;
        while (carry != 0 && k < MAX_LIMBS) {
            uint64_t sum = (uint64_t)result->limbs[k] + carry;
            result->limbs[k] = (uint32_t)sum;
            carry = sum >> 32;
            ++k;
        }
    }
    result->size = a->size + b->size;
    if (result->size > MAX_LIMBS) result->size = MAX_LIMBS;
    bn_normalize(result);
}

// Karatsuba mul (fallback to schoolbook for small sizes)
void bignum_multiply_karatsuba(Bignum* result, const Bignum* a, const Bignum* b) {
    bignum_init(result);
    if (a->size == 0 || b->size == 0) return;

    // 기본 단계: 크기가 작으면 기존 곱셈 방식 사용
    if (a->size < 32 || b->size < 32) {
        bignum_multiply_schoolbook(result, a, b);
        return;
    }

    // 1. 분할 (Divide)
    int m = (a->size > b->size) ? a->size : b->size;
    m = (m + 1) / 2; // 절반 크기

    Bignum a_high, a_low, b_high, b_low;
    bignum_split(a, &a_high, &a_low, m);
    bignum_split(b, &b_high, &b_low, m);

    // 2. 정복 (Conquer) - 3번의 재귀 곱셈
    Bignum z0, z1, z2;
    bignum_multiply_karatsuba(&z0, &a_low, &b_low);     // z0 = a_low * b_low
    bignum_multiply_karatsuba(&z2, &a_high, &b_high);   // z2 = a_high * b_high

    Bignum a_sum, b_sum;
    bignum_add(&a_sum, &a_low, &a_high);
    bignum_add(&b_sum, &b_low, &b_high);
    bignum_multiply_karatsuba(&z1, &a_sum, &b_sum); // z1 = (a_low+a_high)*(b_low+b_high)

    // 중간 항 계산: z1 = z1 - z2 - z0
    bignum_subtract(&z1, &z1, &z2);
    bignum_subtract(&z1, &z1, &z0);

    // 3. 조합 (Combine)
    // result = z2 * B^(2m) + z1 * B^m + z0
    Bignum t1, t2;
    bignum_shift_left(&t1, &z2, 2 * m); // t1 = z2 << (2m)
    bignum_shift_left(&t2, &z1, m);     // t2 = z1 << m

    bignum_add(result, &t1, &t2);
    bignum_add(result, result, &z0);
}

// 최종 곱셈 함수 (현재 Karatsuba 우선)
void bignum_multiply(Bignum* result, const Bignum* a, const Bignum* b) {
    bignum_multiply_karatsuba(result, a, b);
}

/* ====== Division (Knuth-like long division) ====== */

// limb의 선행 0 비트 수를 계산
static int count_leading_zeros(uint32_t x) {
    if (x == 0) return 32;
    int n = 0;
    if ((x & 0xFFFF0000) == 0) { n += 16; x <<= 16; }
    if ((x & 0xFF000000) == 0) { n += 8;  x <<= 8; }
    if ((x & 0xF0000000) == 0) { n += 4;  x <<= 4; }
    if ((x & 0xC0000000) == 0) { n += 2;  x <<= 2; }
    if ((x & 0x80000000) == 0) { n += 1; }
    return n;
}

// n비트 왼쪽 시프트 (a <<= n)
static void bn_shift_left(Bignum* a, int shift) {
    if (shift == 0 || a->size == 0) return;
    int limbs_to_shift = shift / LIMB_BITS;
    int bits_to_shift = shift % LIMB_BITS;

    // limb 단위 전체 이동
    if (limbs_to_shift > 0) {
        int new_size = a->size + limbs_to_shift;
        if (new_size > MAX_LIMBS) { // 오버플로우는 0으로 처리
            bn_zero(a);
            return;
        }
        for (int i = a->size - 1; i >= 0; --i) {
            a->limbs[i + limbs_to_shift] = a->limbs[i];
        }
        for (int i = 0; i < limbs_to_shift; ++i) {
            a->limbs[i] = 0;
        }
        a->size = new_size;
    }

    // 비트 단위 이동
    if (bits_to_shift > 0) {
        uint32_t carry = 0;
        for (int i = 0; i < a->size; ++i) {
            uint64_t v = ((uint64_t)a->limbs[i] << bits_to_shift) | carry;
            a->limbs[i] = (uint32_t)v;
            carry = (uint32_t)(v >> LIMB_BITS);
        }
        if (carry > 0 && a->size < MAX_LIMBS) {
            a->limbs[a->size++] = carry;
        }
    }
    bn_normalize(a);
}

// n비트 오른쪽 시프트 (a >>= n)
static void bn_shift_right(Bignum* a, int shift) {
    if (shift == 0 || a->size == 0) return;
    int limbs_to_shift = shift / LIMB_BITS;
    int bits_to_shift = shift % LIMB_BITS;

    // limb 단위 전체 이동
    if (limbs_to_shift > 0) {
        if (limbs_to_shift >= a->size) {
            bn_zero(a);
            return;
        }
        for (int i = 0; i < a->size - limbs_to_shift; ++i) {
            a->limbs[i] = a->limbs[i + limbs_to_shift];
        }
        a->size -= limbs_to_shift;
        for (int i = a->size; i < a->size + limbs_to_shift && i < MAX_LIMBS; ++i) {
            a->limbs[i] = 0;
        }
    }

    // 비트 단위 이동
    if (bits_to_shift > 0) {
        uint32_t carry = 0;
        for (int i = a->size - 1; i >= 0; --i) {
            uint32_t mask = (bits_to_shift == 32) ? 0xFFFFFFFFu : ((1u << bits_to_shift) - 1);
            uint32_t new_carry = a->limbs[i] & mask;
            a->limbs[i] = (a->limbs[i] >> bits_to_shift) | (carry << (LIMB_BITS - bits_to_shift));
            carry = new_carry;
        }
    }
    bn_normalize(a);
}

// a / b : quotient, remainder (비부호 정수 나눗셈)
void bignum_divide(Bignum* quotient, Bignum* remainder, const Bignum* a, const Bignum* b) {
    if (quotient) bn_zero(quotient);
    if (remainder) bn_zero(remainder);

    if (bn_is_zero(b)) { // 0으로 나누기 -> remainder=a
        if (remainder) bignum_copy(remainder, a);
        return;
    }
    if (bn_ucmp(a, b) < 0) { // a < b -> quotient=0, remainder=a
        if (remainder) bignum_copy(remainder, a);
        return;
    }

    // D1: Normalize so that highest bit of v is 1
    int shift = count_leading_zeros(b->limbs[b->size - 1]);
    Bignum u, v;
    bignum_copy(&u, a);
    bignum_copy(&v, b);
    if (shift > 0) {
        bn_shift_left(&u, shift);
        bn_shift_left(&v, shift);
    }

    if (u.size == MAX_LIMBS) { /* optional: handle overflow */ }
    if (u.size < MAX_LIMBS) u.limbs[u.size++] = 0; // extra space for carries

    int m = u.size;
    int n = v.size;

    Bignum q; bn_zero(&q);
    if (m > n) {
        q.size = m - n + 1;
    }
    else {
        q.size = 1;
    }
    if (q.size > MAX_LIMBS) q.size = MAX_LIMBS;
    memset(q.limbs, 0, q.size * sizeof(uint32_t));

    // D2-D7: Main loop
    for (int j = m - n; j >= 0; --j) {
        uint64_t u_top = ((uint64_t)u.limbs[j + n] << 32) + u.limbs[j + n - 1];
        uint64_t q_hat = u_top / v.limbs[n - 1];
        uint64_t r_hat = u_top % v.limbs[n - 1];

        if (q_hat > 0xFFFFFFFFu) q_hat = 0xFFFFFFFFu;

        // correction
        while (r_hat <= 0xFFFFFFFFu && n > 1 &&
            q_hat * v.limbs[n - 2] > ((r_hat << 32) + u.limbs[j + n - 2])) {
            q_hat--;
            r_hat += v.limbs[n - 1];
            if (r_hat > 0xFFFFFFFFu) break;
        }

        // Multiply and subtract
        uint64_t borrow = 0;
        for (int i = 0; i < n; ++i) {
            uint64_t p = q_hat * v.limbs[i];
            uint64_t sub = (uint64_t)u.limbs[j + i] - (uint32_t)p - borrow;
            u.limbs[j + i] = (uint32_t)sub;
            borrow = (p >> 32) + (sub >> 63); // sub<0 -> borrow++
        }
        uint64_t sub_hi = (uint64_t)u.limbs[j + n] - borrow;
        u.limbs[j + n] = (uint32_t)sub_hi;
        bool under = (sub_hi >> 63);

        if (under) { // add back
            q_hat--;
            uint64_t carry = 0;
            for (int i = 0; i < n; ++i) {
                uint64_t sum = (uint64_t)u.limbs[j + i] + v.limbs[i] + carry;
                u.limbs[j + i] = (uint32_t)sum;
                carry = sum >> 32;
            }
            u.limbs[j + n] += (uint32_t)carry;
        }
        if (j < MAX_LIMBS) q.limbs[j] = (uint32_t)q_hat;
    }

    // D8: Denormalize
    if (quotient) {
        bn_normalize(&q);
        *quotient = q;
    }
    if (remainder) {
        bn_normalize(&u);
        if (shift > 0) bn_shift_right(&u, shift);
        *remainder = u;
    }
}

/* ====== Montgomery multiplication & modular exponentiation ====== */

// n0' = -n[0]^{-1} mod 2^32
static uint32_t mont_n0_inv32(const Bignum* n) {
    uint32_t n0 = (n->size > 0) ? n->limbs[0] : 0;
    // n0는 홀수라고 가정(RSA 모듈러스)
    uint32_t inv = 1;
    for (int i = 0; i < 5; ++i) {
        uint64_t t = (uint64_t)inv * (2u - (uint64_t)n0 * inv);
        inv = (uint32_t)t;
    }
    return (uint32_t)(0u - inv); // -inv mod 2^32
}

// T[0..2k+1] = a*b (정확한 2k-워드 곱; k = n->size)
static void mul_2k_to_T(uint32_t* T, const Bignum* a, const Bignum* b, int k) {
    memset(T, 0, sizeof(uint32_t) * (2 * k + 2));
    for (int i = 0; i < k; ++i) {
        uint64_t carry = 0;
        uint32_t ai = (i < a->size) ? a->limbs[i] : 0;
        for (int j = 0; j < k; ++j) {
            uint32_t bj = (j < b->size) ? b->limbs[j] : 0;
            uint64_t sum = (uint64_t)T[i + j] + (uint64_t)ai * bj + carry;
            T[i + j] = (uint32_t)sum;
            carry = sum >> 32;
        }
        uint64_t acc = (uint64_t)T[i + k] + carry;
        T[i + k] = (uint32_t)acc;
        T[i + k + 1] += (uint32_t)(acc >> 32);
    }
}

// REDC (Montgomery reduction) — CIOS/REDC 형태
// 입력: T = a*b (2k limbs). 출력: r = T * R^{-1} mod n (k limbs)
static void mont_reduce_redc(Bignum* r, uint32_t* T, const Bignum* n, uint32_t n0_inv) {
    const int k = n->size;

    for (int i = 0; i < k; ++i) {
        uint32_t m = (uint32_t)((uint64_t)T[i] * n0_inv); // m ≡ T[i] * n0' (mod base)

        uint64_t carry = 0;
        for (int j = 0; j < k; ++j) {
            uint64_t sum = (uint64_t)T[i + j] + (uint64_t)m * n->limbs[j] + carry;
            T[i + j] = (uint32_t)sum;
            carry = sum >> 32;
        }

        int z = i + k;
        while (carry > 0 && z < (2 * k + 2)) {
            uint64_t sum = (uint64_t)T[z] + carry;
            T[z] = (uint32_t)sum;
            carry = sum >> 32;
            z++;
        }
    }

    // 결과 후보는 상위 k 워드 (T가 R^k 만큼 암묵적으로 시프트됨)
    // T의 상위 limb (T[k]부터)가 n보다 큰지 확인
    bool final_borrow = false;
    uint64_t borrow = 0;
    for (int i = 0; i < k; ++i) {
        uint64_t diff = (uint64_t)T[k + i] - n->limbs[i] - borrow;
        r->limbs[i] = (uint32_t)diff;
        borrow = (diff >> 63) & 1;
    }
    // 최종 borrow가 있다면 T[k..] < n 이므로, T[k..]를 그대로 사용
    // borrow가 없다면 T[k..] >= n 이므로, 뺀 결과인 r을 사용
    if (!borrow) {
        r->size = k;
        bn_normalize(r);
    }
    else {
        r->size = k;
        memcpy(r->limbs, &T[k], k * sizeof(uint32_t));
        bn_normalize(r);
    }
}

// (일반값 a, b) → r = a*b mod n  (Montgomery 내부 핵심)
static void mont_mul_core(Bignum* r, const Bignum* a, const Bignum* b, const Bignum* n, uint32_t n0_inv) {
    Bignum A = *a, B = *b;
    bn_mod(&A, n);
    bn_mod(&B, n);

    const int k = n->size;
    uint32_t T[2 * MAX_LIMBS + 2]; // 충분한 여유
    mul_2k_to_T(T, &A, &B, k);
    mont_reduce_redc(r, T, n, n0_inv);
}

// R^2 mod n 계산 (R = base^k, base=2^32). 2k회 limb-시프트 후 매번 mod로 크기 제어
static void compute_R2_mod(const Bignum* n, Bignum* R2) {
    bignum_init(R2);
    R2->size = 1; R2->limbs[0] = 1u; // 1
    int k = n->size;
    for (int i = 0; i < 2 * k; ++i) {
        // * (2^32) mod n
        bn_shift_left(R2, 32);
        bn_mod(R2, n);
    }
}

// a(일반) → aR mod n
static void to_mont(Bignum* out, const Bignum* a, const Bignum* n, uint32_t n0_inv, const Bignum* R2) {
    mont_mul_core(out, a, R2, n, n0_inv); // a * R^2 * R^{-1} = aR
}

// A(몽고메리) → A * R^{-1} mod n (일반 영역)
static void from_mont(Bignum* out, const Bignum* A, const Bignum* n, uint32_t n0_inv) {
    Bignum one; bignum_init(&one); one.size = 1; one.limbs[0] = 1u;
    mont_mul_core(out, A, &one, n, n0_inv); // A * 1 * R^{-1}
}

/* ---- (교체) 모듈러 곱: Montgomery 기반 ---- */
// r = (a*b) mod m
void bn_mod_mul(Bignum* r, const Bignum* a, const Bignum* b, const Bignum* m) {
    if (bn_is_zero(m)) { bn_zero(r); return; }
    if (bn_is_zero(a) || bn_is_zero(b)) { bn_zero(r); return; }

    uint32_t n0_inv = mont_n0_inv32(m);
    Bignum R2; compute_R2_mod(m, &R2);

    Bignum A_, B_; bignum_init(&A_); bignum_init(&B_);
    to_mont(&A_, a, m, n0_inv, &R2);
    to_mont(&B_, b, m, n0_inv, &R2);

    Bignum C_; mont_mul_core(&C_, &A_, &B_, m, n0_inv);

    from_mont(r, &C_, m, n0_inv);
}

// result = a mod m
void bignum_mod(Bignum* result, const Bignum* a, const Bignum* m) {
    Bignum q, r;
    bignum_divide(&q, &r, a, m);
    bignum_copy(result, &r);
}

/* ---- 모듈러 거듭제곱: Montgomery 기반 ---- */
// result = base^exp mod modulus
void bignum_mod_exp(Bignum* result, const Bignum* base, const Bignum* exp, const Bignum* modulus) {
    if (bn_is_zero(modulus)) { bn_zero(result); return; }

    // 1. base를 modulus로 나눈 나머지로 정규화하여 안전성 확보
    Bignum base_reduced;
    bignum_mod(&base_reduced, base, modulus);

    // 2. 이제부터 안전하게 정규화된 base_reduced를 사용
    uint32_t n0_inv = mont_n0_inv32(modulus);
    Bignum R2; compute_R2_mod(modulus, &R2);

    Bignum base_m; to_mont(&base_m, &base_reduced, modulus, n0_inv, &R2);

    Bignum one; bignum_init(&one); one.size = 1; one.limbs[0] = 1u;
    Bignum r_m; to_mont(&r_m, &one, modulus, n0_inv, &R2);

    // ... 이하 코드는 동일 ...
    int nbits = bn_bit_length(exp);
    for (int i = nbits - 1; i >= 0; --i) {
        mont_mul_core(&r_m, &r_m, &r_m, modulus, n0_inv);
        if (bn_get_bit(exp, i)) {
            mont_mul_core(&r_m, &r_m, &base_m, modulus, n0_inv);
        }
    }

    from_mont(result, &r_m, modulus, n0_inv);
}