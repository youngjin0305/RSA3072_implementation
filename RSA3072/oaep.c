/*
 * RSAES-OAEP Padding 구현 (테스트용 dummy SHA-256 사용)
 *
 * 동작 과정:
 * 1. 라벨 L을 해시한 lHash 준비 (여기서는 dummy 해시 사용).
 * 2. 데이터 블록(DB) 구성:
 *      DB = lHash || PS || 0x01 || M
 *      - PS: 0x00 패딩
 *      - M : 평문 메시지
 * 3. 랜덤 seed를 사용해 MGF1으로 dbMask 생성 후
 *      maskedDB = DB XOR dbMask
 * 4. maskedDB를 사용해 MGF1으로 seedMask 생성 후
 *      maskedSeed = seed XOR seedMask
 * 5. 최종 암호화 입력 블록(EM) 구성:
 *      EM = 0x00 || maskedSeed || maskedDB
 *
 * 이 EM을 RSA 모듈러 거듭제곱에 넣어 암호화를 수행함.
 * 실제 구현에서는 SHA-256 해시를 사용해야 하나, 
 * 본 코드는 테스트 목적으로 dummy 해시 함수를 사용.
 */

#include "rsa.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>



// 테스트를 위해 고정된 값을 반환하는 더미 함수를 사용
static void dummy_sha256(const unsigned char *data, size_t len, unsigned char *out) {
    // SHA256("test")
    unsigned char dummy_hash[32] = {
        0x94, 0x11, 0x58, 0x6e, 0x48, 0x76, 0x6f, 0x3d,
        0x56, 0x7b, 0x14, 0x98, 0x77, 0x05, 0x77, 0x9a,
        0x32, 0x18, 0x18, 0x8a, 0x47, 0x47, 0xa1, 0x01,
        0x0c, 0xf0, 0x6f, 0x56, 0x90, 0x24, 0x18, 0x86
    };
    memcpy(out, dummy_hash, 32);
}

// MGF1 마스크 생성 함수 (SHA-256 기반)
static int rsa_mgf1(unsigned char* mask, size_t mask_len, const unsigned char* seed, size_t seed_len) {
    unsigned char counter_be[4];
    unsigned char digest[32];
    size_t generated = 0;

    for (uint32_t counter = 0; generated < mask_len; counter++) {
        counter_be[0] = (unsigned char)((counter >> 24) & 0xFF);
        counter_be[1] = (unsigned char)((counter >> 16) & 0xFF);
        counter_be[2] = (unsigned char)((counter >> 8) & 0xFF);
        counter_be[3] = (unsigned char)(counter & 0xFF);

        // 동적 메모리 할당으로 변경
        unsigned char* combined = (unsigned char*)malloc(seed_len + 4);
        if (!combined) {
            return -1; // 메모리 할당 실패
        }
        memcpy(combined, seed, seed_len);
        memcpy(combined + seed_len, counter_be, 4);

        // 해시 계산
        dummy_sha256(combined, seed_len + 4, digest);
        
        // 동적 할당 메모리 해제
        free(combined);

        size_t to_copy = (mask_len - generated < 32) ? (mask_len - generated) : 32;
        memcpy(mask + generated, digest, to_copy);
        generated += to_copy;
    }
    return 1;
}

// RSAES-OAEP 패딩 함수
int rsa_oaep_pad(unsigned char* out, const unsigned char* msg, size_t msg_len, size_t k, const unsigned char* seed) {
    size_t hLen = 32;
    if (msg_len > k - 2 * hLen - 2) {
        fprintf(stderr, "메시지 길이가 너무 깁니다.\n");
        return -1;
    }

    unsigned char lHash[hLen];
    dummy_sha256(NULL, 0, lHash);

    size_t ps_len = k - msg_len - 2 * hLen - 2;
    unsigned char* DB = (unsigned char*)malloc(hLen + ps_len + 1 + msg_len);
    if (!DB) return -1;
    unsigned char* p = DB;
    memcpy(p, lHash, hLen); p += hLen;
    memset(p, 0x00, ps_len); p += ps_len;
    *p++ = 0x01;
    memcpy(p, msg, msg_len);

    size_t db_len = hLen + ps_len + 1 + msg_len;
    unsigned char* dbMask = (unsigned char*)malloc(db_len);
    if (!dbMask) { free(DB); return -1; }
    rsa_mgf1(dbMask, db_len, seed, hLen);

    unsigned char* maskedDB = (unsigned char*)malloc(db_len);
    if (!maskedDB) { free(DB); free(dbMask); return -1; }
    for (size_t i = 0; i < db_len; i++) {
        maskedDB[i] = DB[i] ^ dbMask[i];
    }

    unsigned char* seedMask = (unsigned char*)malloc(hLen);
    if (!seedMask) { free(DB); free(dbMask); free(maskedDB); return -1; }
    rsa_mgf1(seedMask, hLen, maskedDB, db_len);

    unsigned char* maskedSeed = (unsigned char*)malloc(hLen);
    if (!maskedSeed) { free(DB); free(dbMask); free(maskedDB); free(seedMask); return -1; }
    for (size_t i = 0; i < hLen; i++) {
        maskedSeed[i] = seed[i] ^ seedMask[i];
    }

    out[0] = 0x00;
    memcpy(out + 1, maskedSeed, hLen);
    memcpy(out + 1 + hLen, maskedDB, db_len);

    free(DB); free(dbMask); free(maskedDB); free(seedMask); free(maskedSeed);
    return 0;
}