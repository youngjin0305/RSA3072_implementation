/*
 * RSA-3072 OAEP 패딩 (SHA-256, 테스트용 dummy hash)
 *
 * 고정 크기 버퍼만 사용 (동적 할당 없음, VLA 사용 안 함)
 *
 * 계산 근거:
 *  - RSA key length k = 3072 bits = 384 bytes
 *  - SHA-256 hash length hLen = 32 bytes
 *  - max message length for OAEP: m_max = k - 2*hLen - 2 = 318 bytes
 *  - DB max length: db_max = k - hLen - 1 = 351 bytes
 *  - MGF1 combined buffer size (seed+hCounter) = hLen + 4 = 36 bytes
 *
 * 사용법:
 *  - out 버퍼은 반드시 k(=384) 바이트 이상이어야 함.
 *  - seed 길이는 hLen(=32) 바이트여야 함.
 *  - msg_len <= m_max 이어야 함.
 *
 * 주의:
 *  - 이 코드는 테스트용 dummy_sha256 사용. 실제 사용 시에는 SHA256() 등으로 교체하세요.
 */

#include "rsa.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#define RSA3072_K_BYTES 384
#define OAEP_HLEN 32
#define OAEP_DB_MAX (RSA3072_K_BYTES - OAEP_HLEN - 1) /* 351 */
#define OAEP_M_MAX (RSA3072_K_BYTES - 2*OAEP_HLEN - 2) /* 318 */
#define MGF1_COMBINED_MAX (OAEP_HLEN + 4) /* 36 */
#define SHA256_DIGEST_LEN OAEP_HLEN

/* --- 테스트용 더미 SHA-256 (실사용 시 실제 SHA256으로 교체) --- */
static void dummy_sha256(const unsigned char *data, size_t len, unsigned char *out32) {
    (void)data; (void)len;
    static const unsigned char dummy_hash[SHA256_DIGEST_LEN] = {
        0x94,0x11,0x58,0x6e,0x48,0x76,0x6f,0x3d,
        0x56,0x7b,0x14,0x98,0x77,0x05,0x77,0x9a,
        0x32,0x18,0x18,0x8a,0x47,0x47,0xa1,0x01,
        0x0c,0xf0,0x6f,0x56,0x90,0x24,0x18,0x86
    };
    memcpy(out32, dummy_hash, SHA256_DIGEST_LEN);
}

/* --- MGF1 (SHA-256 기반) ---
 * mask: 출력 버퍼 (mask_len 바이트)
 * mask_len: 생성할 마스크 길이
 * seed: 입력 시드 (seed_len 바이트)
 * seed_len: seed 길이 (OAEP에서는 hLen 이어야 함)
 * 반환: 1 성공, 0 실패
 */
static int rsa_mgf1_fixed(unsigned char *mask, size_t mask_len,
                          const unsigned char *seed, size_t seed_len) {
    if (!mask || !seed) return 0;
    if (seed_len != OAEP_HLEN) return 0; /* OAEP 사용 가정 */

    unsigned char digest[SHA256_DIGEST_LEN];
    unsigned char combined[MGF1_COMBINED_MAX]; /* seed (32) + counter (4) */
    size_t generated = 0;
    uint32_t counter = 0;

    while (generated < mask_len) {
        /* combined = seed || COUNTER_BE */
        memcpy(combined, seed, seed_len);
        combined[seed_len + 0] = (unsigned char)((counter >> 24) & 0xFF);
        combined[seed_len + 1] = (unsigned char)((counter >> 16) & 0xFF);
        combined[seed_len + 2] = (unsigned char)((counter >> 8) & 0xFF);
        combined[seed_len + 3] = (unsigned char)(counter & 0xFF);

        /* 해시 */
        dummy_sha256(combined, seed_len + 4, digest);

        size_t to_copy = ((mask_len - generated) < SHA256_DIGEST_LEN) ? (mask_len - generated) : SHA256_DIGEST_LEN;
        memcpy(mask + generated, digest, to_copy);
        generated += to_copy;
        counter++;
    }
    return 1;
}

/* --- OAEP 인코딩 (고정 버퍼 사용, 동적할당 없음)
 * out: EM (출력), 길이 k (=RSA3072_K_BYTES) 바이트 이상이어야 함
 * msg: 평문
 * msg_len: 평문 길이 (<= OAEP_M_MAX)
 * k: RSA 모듈러스 길이 바이트 (여기서는 RSA3072_K_BYTES)
 * seed: OAEP 시드 (길이 OAEP_HLEN)
 * 반환: 0 성공, -1 실패
 */
int rsa_oaep_pad(unsigned char *out, const unsigned char *msg, size_t msg_len,
                       size_t k, const unsigned char *seed) {
    if (!out || !msg || !seed) return -1;
    if (k != RSA3072_K_BYTES) return -1; /* 이 함수는 RSA-3072 전용 */
    if (msg_len > OAEP_M_MAX) return -1;
    /* seed 길이는 OAEP_HLEN 이어야 함 (호출자 책임) */

    /* lHash */
    unsigned char lHash[OAEP_HLEN];
    dummy_sha256((const unsigned char *)"", 0, lHash); /* 안전한 빈 라벨 해시 */

    /* DB 생성: 길이 = db_len = OAEP_DB_MAX - (최대 PS 길이를 고려해 실제 db_len = hLen + PS + 1 + msg_len) */
    size_t db_len = OAEP_HLEN + ( (RSA3072_K_BYTES - OAEP_HLEN - 1) - (OAEP_HLEN + 1 + msg_len) ) + 1 + msg_len;
    /* 위 식은 복잡해 보이지만 안전을 위해 아래와 같이 직접 계산(간단): */
    /* 실제 PS_len = k - msg_len - 2*hLen - 2 */
    size_t ps_len = k - msg_len - 2*OAEP_HLEN - 2;
    db_len = OAEP_HLEN + ps_len + 1 + msg_len;
    if (db_len > OAEP_DB_MAX) return -1; /* 안전 체크 */

    /* 고정 크기 내부 버퍼 */
    unsigned char DB[OAEP_DB_MAX];
    unsigned char dbMask[OAEP_DB_MAX];
    unsigned char maskedDB[OAEP_DB_MAX];
    unsigned char seedMask[OAEP_HLEN];
    unsigned char maskedSeed[OAEP_HLEN];

    /* DB = lHash || PS || 0x01 || M */
    unsigned char *p = DB;
    memcpy(p, lHash, OAEP_HLEN); p += OAEP_HLEN;
    if (ps_len) memset(p, 0x00, ps_len);
    p += ps_len;
    *p++ = 0x01;
    memcpy(p, msg, msg_len);

    /* dbMask = MGF1(seed, db_len) */
    if (!rsa_mgf1_fixed(dbMask, db_len, seed, OAEP_HLEN)) return -1;

    /* maskedDB = DB XOR dbMask */
    for (size_t i = 0; i < db_len; ++i) maskedDB[i] = DB[i] ^ dbMask[i];

    /* seedMask = MGF1(maskedDB, hLen) */
    if (!rsa_mgf1_fixed(seedMask, OAEP_HLEN, maskedDB, db_len)) return -1;

    /* maskedSeed = seed XOR seedMask */
    for (size_t i = 0; i < OAEP_HLEN; ++i) maskedSeed[i] = seed[i] ^ seedMask[i];

    /* EM = 0x00 || maskedSeed || maskedDB  (length k) */
    out[0] = 0x00;
    memcpy(out + 1, maskedSeed, OAEP_HLEN);
    memcpy(out + 1 + OAEP_HLEN, maskedDB, db_len);

    /* 남은 바이트(정확히 k 바이트를 쓰는지 검증하거나, 호출자가 k 바이트로 초기화할 것) */
    return 0;
}
