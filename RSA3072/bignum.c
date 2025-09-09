#include "bignum.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define LIMB_BITS 32u

// ---------- 내부 유틸 ----------
static void bn_normalize(Bignum* x) {
    while (x->size > 0 && x->limbs[x->size - 1] == 0) x->size--;
}

static void bn_reserve(Bignum* x, size_t cap) {
    if (cap <= x->capacity) return;
    size_t ncap = x->capacity ? x->capacity : 1;
    while (ncap < cap) ncap <<= 1;
    x->limbs = (uint32_t*)realloc(x->limbs, ncap * sizeof(uint32_t));
    // 새로 늘어난 부분 0으로
    for (size_t i = x->capacity; i < ncap; ++i) x->limbs[i] = 0;
    x->capacity = ncap;
}

static void bn_set_zero(Bignum* x) { x->size = 0; }

static int bn_is_zero(const Bignum* x) { return x->size == 0; }

static size_t bn_bit_length(const Bignum* x) {
    if (x->size == 0) return 0;
    uint32_t ms = x->limbs[x->size - 1];
    unsigned leading = 0;
    // 최상위 limb의 최상위 1비트 위치
    if (ms == 0) return (x->size - 1) * LIMB_BITS; // 방어적(정상화되면 오지 않음)
    uint32_t t = ms;
    while ((t & 0x80000000u) == 0) { t <<= 1; leading++; }
    unsigned msb_index = 31 - leading;
    return (x->size - 1) * LIMB_BITS + (size_t)msb_index + 1;
}

static int bn_get_bit(const Bignum* x, size_t bit) {
    size_t w = bit / LIMB_BITS, r = bit % LIMB_BITS;
    if (w >= x->size) return 0;
    return (int)((x->limbs[w] >> r) & 1u);
}

static void bn_set_bit(Bignum* x, size_t bit) {
    size_t w = bit / LIMB_BITS, r = bit % LIMB_BITS;
    bn_reserve(x, w + 1);
    while (x->size < w + 1) x->limbs[x->size++] = 0;
    x->limbs[w] |= (uint32_t)(1u << r);
}

static void bn_shift_left1(Bignum* x) {
    if (x->size == 0) return;
    bn_reserve(x, x->size + 1);
    uint32_t carry = 0;
    for (size_t i = 0; i < x->size; ++i) {
        uint64_t v = ((uint64_t)x->limbs[i] << 1) | carry;
        x->limbs[i] = (uint32_t)v;
        carry = (uint32_t)(v >> 32);
    }
    if (carry) x->limbs[x->size++] = carry;
}

static void bn_shift_left_small(Bignum* x, unsigned bits) {
    if (bits == 0 || x->size == 0) return;
    assert(bits < 32);
    bn_reserve(x, x->size + 1);
    uint32_t carry = 0;
    for (size_t i = 0; i < x->size; ++i) {
        uint64_t v = ((uint64_t)x->limbs[i] << bits) | carry;
        x->limbs[i] = (uint32_t)v;
        carry = (uint32_t)(v >> 32);
    }
    if (carry) x->limbs[x->size++] = carry;
}

static void bn_add_small(Bignum* x, uint32_t add) {
    bn_reserve(x, x->size + 1);
    uint64_t c = add;
    size_t i = 0;
    while (c) {
        if (i >= x->size) {
            x->limbs[x->size++] = (uint32_t)c;
            c >>= 32;
            break;
        }
        uint64_t v = (uint64_t)x->limbs[i] + c;
        x->limbs[i] = (uint32_t)v;
        c = v >> 32;
        i++;
    }
}

// ---------- 공개 API 구현 ----------
void bignum_init(Bignum* bn) {
    bn->limbs = NULL;
    bn->size = 0;
    bn->capacity = 0;
}

void bignum_free(Bignum* bn) {
    if (bn->limbs) free(bn->limbs);
    bn->limbs = NULL;
    bn->size = bn->capacity = 0;
}

void bignum_copy(Bignum* dest, const Bignum* src) {
    if (dest == src) return;
    if (src->size == 0) { bn_set_zero(dest); return; }
    bn_reserve(dest, src->size);
    memcpy(dest->limbs, src->limbs, src->size * sizeof(uint32_t));
    dest->size = src->size;
    // 상위 여유 limb는 그대로 두어도 무방
}

static int hex_val(int c) {
    if ('0' <= c && c <= '9') return c - '0';
    if ('a' <= c && c <= 'f') return c - 'a' + 10;
    if ('A' <= c && c <= 'F') return c - 'A' + 10;
    return -1;
}

int bignum_from_hex(Bignum* bn, const char* hex_str) {
    bn_set_zero(bn);
    if (!hex_str) return -1;

    // 앞 공백/0x 제거
    while (*hex_str == ' ' || *hex_str == '\t' || *hex_str == '\n' || *hex_str == '_') hex_str++;
    if (hex_str[0] == '0' && (hex_str[1] == 'x' || hex_str[1] == 'X')) hex_str += 2;
    // 전부 0이면 0 처리
    const char* p = hex_str;
    int any = 0;
    while (*p) {
        int v = hex_val(*p);
        if (v >= 0) { any = 1; break; }
        else if (*p == ' ' || *p == '\t' || *p == '\n' || *p == '_') { p++; continue; }
        else break;
    }
    if (!any) return 0;

    // 누적: x = (x << 4) + nibble
    for (; *hex_str; ++hex_str) {
        if (*hex_str == ' ' || *hex_str == '\t' || *hex_str == '\n' || *hex_str == '_') continue;
        int v = hex_val(*hex_str);
        if (v < 0) return -2;
        bn_shift_left_small(bn, 4);
        bn_add_small(bn, (uint32_t)v);
    }
    bn_normalize(bn);
    return 0;
}

char* bignum_to_hex(const Bignum* bn) {
    if (bn->size == 0) {
        char* z = (char*)malloc(2);
        z[0] = '0'; z[1] = '\0';
        return z;
    }
    static const char* HEX = "0123456789abcdef";

    // 최상위 limb에서 유효 nibble 개수 계산
    uint32_t ms = bn->limbs[bn->size - 1];
    int first_nibble = 7;
    while (first_nibble > 0 && ((ms >> (first_nibble * 4)) & 0xF) == 0) first_nibble--;

    size_t digits = (size_t)first_nibble + 1 + (bn->size - 1) * 8;
    char* out = (char*)malloc(digits + 1);
    size_t pos = 0;

    // 최상위 limb 출력(앞의 0 nibble 제거)
    for (int i = first_nibble; i >= 0; --i) {
        out[pos++] = HEX[(ms >> (i * 4)) & 0xF];
    }
    // 나머지는 항상 8 nibble(0 패딩 포함)
    for (size_t w = bn->size - 1; w-- > 0; ) {
        uint32_t limb = bn->limbs[w];
        for (int i = 7; i >= 0; --i) out[pos++] = HEX[(limb >> (i * 4)) & 0xF];
    }
    out[digits] = '\0';
    return out;
}

int bignum_compare(const Bignum* a, const Bignum* b) {
    if (a->size != b->size) return (a->size > b->size) ? 1 : -1;
    for (size_t i = a->size; i-- > 0; ) {
        if (a->limbs[i] != b->limbs[i]) return (a->limbs[i] > b->limbs[i]) ? 1 : -1;
    }
    return 0;
}

void bignum_add(Bignum* result, const Bignum* a, const Bignum* b) {
    const Bignum* x = a; const Bignum* y = b;
    if (x->size < y->size) { x = b; y = a; } // x가 더 큼

    bn_reserve(result, x->size + 1);
    uint64_t carry = 0;
    size_t i = 0;
    for (; i < y->size; ++i) {
        uint64_t v = (uint64_t)x->limbs[i] + y->limbs[i] + carry;
        result->limbs[i] = (uint32_t)v;
        carry = v >> 32;
    }
    for (; i < x->size; ++i) {
        uint64_t v = (uint64_t)x->limbs[i] + carry;
        result->limbs[i] = (uint32_t)v;
        carry = v >> 32;
    }
    result->size = x->size;
    if (carry) result->limbs[result->size++] = (uint32_t)carry;
}

void bignum_subtract(Bignum* result, const Bignum* a, const Bignum* b) {
    if (bignum_compare(a, b) < 0) { // 음수는 지원 안 함
        bn_set_zero(result);
        return;
    }
    bn_reserve(result, a->size);
    int64_t borrow = 0;
    size_t i = 0;
    for (; i < b->size; ++i) {
        int64_t v = (int64_t)a->limbs[i] - b->limbs[i] - borrow;
        if (v < 0) { v += ((int64_t)1 << 32); borrow = 1; } else borrow = 0;
        result->limbs[i] = (uint32_t)v;
    }
    for (; i < a->size; ++i) {
        int64_t v = (int64_t)a->limbs[i] - borrow;
        if (v < 0) { v += ((int64_t)1 << 32); borrow = 1; } else borrow = 0;
        result->limbs[i] = (uint32_t)v;
    }
    result->size = a->size;
    bn_normalize(result);
}

void bignum_multiply(Bignum* result, const Bignum* a, const Bignum* b) {
    if (bn_is_zero(a) || bn_is_zero(b)) { bn_set_zero(result); return; }
    bn_reserve(result, a->size + b->size);
    // 0으로 초기화
    for (size_t i = 0; i < a->size + b->size; ++i) result->limbs[i] = 0;

    for (size_t i = 0; i < a->size; ++i) {
        uint64_t carry = 0;
        uint64_t ai = a->limbs[i];
        for (size_t j = 0; j < b->size; ++j) {
            uint64_t idx = i + j;
            __uint128_t cur = (__uint128_t)result->limbs[idx] + ai * (uint64_t)b->limbs[j] + carry;
            result->limbs[idx] = (uint32_t)cur;
            carry = (uint64_t)(cur >> 32);
        }
        result->limbs[i + b->size] = (uint32_t)carry;
    }
    result->size = a->size + b->size;
    bn_normalize(result);
}

// 이진(long) 나눗셈: 비트 단위로 a에서 내려오며 r 유지, r>=b면 빼고 q의 해당 비트 1
void bignum_divide(Bignum* quotient, Bignum* remainder, const Bignum* a, const Bignum* b) {
    if (quotient) bn_set_zero(quotient);
    if (remainder) bn_set_zero(remainder);

    if (bn_is_zero(b) || bn_is_zero(a)) return;

    if (bignum_compare(a, b) < 0) {
        if (remainder) bignum_copy(remainder, a);
        return;
    }

    Bignum r; bignum_init(&r);
    // r는 점차 커질 수 있으니 a.size+1 정도 확보
    bn_reserve(&r, a->size + 1);

    Bignum qtmp; bignum_init(&qtmp);

    size_t nbits = bn_bit_length(a);
    for (size_t idx = nbits; idx-- > 0; ) {
        // r <<= 1
        bn_shift_left1(&r);
        // r의 LSB에 a의 idx 비트 주입
        if (bn_get_bit(a, idx)) {
            if (r.size == 0) { bn_reserve(&r, 1); r.limbs[0] = 1; r.size = 1; }
            else r.limbs[0] |= 1u;
        }
        // if r >= b: r -= b; q[idx]=1
        if (bignum_compare(&r, b) >= 0) {
            Bignum tmp; bignum_init(&tmp);
            bignum_subtract(&tmp, &r, b);
            bignum_free(&r);
            r = tmp;
            bn_set_bit(&qtmp, idx);
        }
    }

    if (quotient) { bignum_copy(quotient, &qtmp); }
    if (remainder) { bignum_copy(remainder, &r); }
    bignum_free(&qtmp);
    bignum_free(&r);
}

void bignum_mod_exp(Bignum* result, const Bignum* base, const Bignum* exp, const Bignum* modulus) {
    // edge
    if (bn_is_zero(modulus)) { bn_set_zero(result); return; }

    // result = 1
    Bignum one; bignum_init(&one);
    bn_reserve(&one, 1); one.limbs[0] = 1; one.size = 1;

    Bignum res; bignum_init(&res);
    bignum_copy(&res, &one);

    // base_mod = base % modulus
    Bignum base_mod; bignum_init(&base_mod);
    Bignum q, r; bignum_init(&q); bignum_init(&r);
    bignum_divide(&q, &r, base, modulus); // r = base % mod
    bignum_copy(&base_mod, &r);

    size_t ebits = bn_bit_length(exp);
    for (size_t i = 0; i < ebits; ++i) {
        if (bn_get_bit(exp, i)) {
            // res = (res * base_mod) % modulus
            Bignum mul; bignum_init(&mul);
            bignum_multiply(&mul, &res, &base_mod);
            Bignum q2, r2; bignum_init(&q2); bignum_init(&r2);
            bignum_divide(&q2, &r2, &mul, modulus);
            bignum_free(&mul);
            bignum_free(&res);
            res = r2;
            bignum_free(&q2);
        }
        // base_mod = (base_mod * base_mod) % modulus
        Bignum sq; bignum_init(&sq);
        bignum_multiply(&sq, &base_mod, &base_mod);
        Bignum q3, r3; bignum_init(&q3); bignum_init(&r3);
        bignum_divide(&q3, &r3, &sq, modulus);
        bignum_free(&sq);
        bignum_free(&base_mod);
        base_mod = r3;
        bignum_free(&q3);
    }

    bignum_copy(result, &res);

    bignum_free(&res);
    bignum_free(&base_mod);
    bignum_free(&one);
    bignum_free(&q);
    bignum_free(&r);
}
