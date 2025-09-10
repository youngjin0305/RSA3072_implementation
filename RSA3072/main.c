#include "rsa.h"
#include "oaep.h" // OAEP 패딩을 위해 추가
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// RSAES_(3072)(3)(SHA256)_ENT.txt
// RSAES_(3072)(3)(SHA256)_DET.txt

// ========== 헥스 문자열 → 바이트 배열 변환 ==========
static int hex_to_bytes(const char *hex, unsigned char *out, int max_len) {
    if (!hex) return 0;
    int len = strlen(hex);
    if (len % 2 != 0) {
        fprintf(stderr, "Invalid hex string length: %d\n", len);
        return -1;
    }
    int out_len = len / 2;
    if (out_len > max_len) {
        fprintf(stderr, "Output buffer too small: %d > %d\n", out_len, max_len);
        return -1;
    }
    for (int i = 0; i < out_len; i++) {
        if (sscanf(hex + 2*i, "%2hhx", &out[i]) != 1) {
            fprintf(stderr, "Failed to parse hex at index %d\n", i);
            return -1;
        }
    }
    return out_len;
}

// ========== ENT 벡터 테스트 함수 ==========
int test_ent_vector(const char* filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        printf("[-] Failed to open %s\n", filename);
        return 0;
    }
    printf("[*] Testing with %s\n", filename);

    char line[4096];
    char key[64], value[4096];
    Bignum n, e, m, c_expected, c_actual;
    bignum_init(&n); bignum_init(&e); bignum_init(&m); bignum_init(&c_expected); bignum_init(&c_actual);

    int test_passed = 1;
    int test_count = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "%63[^=] = %4095s", key, value) == 2) {
            if (strcmp(key, "n ") == 0) {
                bignum_from_hex(&n, value);
            } else if (strcmp(key, "e ") == 0) {
                bignum_from_hex(&e, value);
            } else if (strcmp(key, "Msg ") == 0) {
                bignum_from_hex(&m, value);
            } else if (strcmp(key, "Ciphertext ") == 0) {
                bignum_from_hex(&c_expected, value);
                
                RSA_PublicKey pub;
                pub.n = n;
                pub.e = e;
                rsa_encrypt(&c_actual, &m, &pub);

                test_count++;
                if (bignum_compare(&c_actual, &c_expected) != 0) {
                    printf("[-] Test %d failed! (ENT)\n", test_count);
                    test_passed = 0;
                }
            }
        }
    }

    fclose(fp);
    if (test_passed) {
        printf("[+] All %d ENT tests passed!\n", test_count);
    } else {
        printf("[-] Some ENT tests failed.\n");
    }
    return test_passed;
}

// ========== DET 벡터 테스트 함수 ==========
int test_det_vector(const char* filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        printf("[-] Failed to open %s\n", filename);
        return 0;
    }
    printf("[*] Testing with %s\n", filename);

    char line[4096];
    char key[64], value[4096];
    Bignum n, e, C, C_actual;
    unsigned char msg_bytes[1024], seed_bytes[32], em_bytes[RSA_KEY_BITS/8];
    size_t msg_len, seed_len;
    
    int test_passed = 1;
    int test_count = 0;
    int test_ready = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "%63[^=] = %4095s", key, value) == 2) {
            if (strcmp(key, "n ") == 0) {
                bignum_init(&n); bignum_from_hex(&n, value);
            } else if (strcmp(key, "e ") == 0) {
                bignum_init(&e); bignum_from_hex(&e, value);
            } else if (strcmp(key, "M ") == 0) {
                msg_len = hex_to_bytes(value, msg_bytes, sizeof(msg_bytes));
            } else if (strcmp(key, "Seed ") == 0) {
                seed_len = hex_to_bytes(value, seed_bytes, sizeof(seed_bytes));
            } else if (strcmp(key, "C ") == 0) {
                bignum_init(&C); bignum_from_hex(&C, value);
                test_ready = 1;
            }
        }
        
        if (test_ready) {
            test_count++;
            
            // 1. OAEP 패딩 적용 (oaep.h에서 호출)
            int rsa_size_bytes = RSA_KEY_BITS / 8;
            rsa_oaep_pad(em_bytes, msg_bytes, msg_len, rsa_size_bytes, seed_bytes);

            // 2. 패딩된 메시지를 Bignum으로 변환
            Bignum em_bn;
            bignum_init(&em_bn);
            for (int i = 0; i < rsa_size_bytes; i++) {
                int limb_idx = i / 4;
                int byte_idx = i % 4;
                em_bn.limbs[limb_idx] |= ((uint32_t)em_bytes[i]) << (byte_idx * 8);
            }
            em_bn.size = rsa_size_bytes / 4;
            while (em_bn.size > 0 && em_bn.limbs[em_bn.size - 1] == 0) {
                em_bn.size--;
            }

            // 3. 암호화 수행
            RSA_PublicKey pub_key = { .n = n, .e = e };
            rsa_encrypt(&C_actual, &em_bn, &pub_key);

            // 4. 결과 비교
            if (bignum_compare(&C_actual, &C) != 0) {
                printf("[-] Test %d failed! (DET)\n", test_count);
                test_passed = 0;
            } else {
                printf("[+] Test %d passed (DET)\n", test_count);
            }
            test_ready = 0;
        }
    }
    
    fclose(fp);
    if (test_passed) {
        printf("[+] All %d DET tests passed!\n", test_count);
    } else {
        printf("[-] Some DET tests failed.\n");
    }
    return test_passed;
}

int main() {
    int overall_ok = 1;

    // RSA 키 생성 파트 (현재는 구현되어 있지 않으므로 주석 처리)
    /*
    Bignum p, q, d, dP, dQ, qInv;
    RSA_PublicKey pub_key;
    RSA_PrivateKey priv_key;

    // generate_prime 함수를 사용하여 p와 q 생성
    generate_prime(&p, RSA_PRIME_BITS);
    generate_prime(&q, RSA_PRIME_BITS);

    // rsa_generate_keys 함수를 사용하여 키 쌍 생성
    rsa_generate_keys(&pub_key, &priv_key, &p, &q);
    */

    // ENT 테스트 벡터 실행 (OAEP 패딩 없는 원시 암호화)
    if (!test_ent_vector("RSAES_(3072)(3)(SHA256)_ENT.txt")) {
        overall_ok = 0;
    }
    printf("\n");

    // DET 테스트 벡터 실행 (OAEP 패딩 있는 암호화)
    if (!test_det_vector("RSAES_(3072)(3)(SHA256)_DET.txt")) {
        overall_ok = 0;
    }
    printf("\n");

    if (overall_ok) {
        printf("[+] All tests completed successfully.\n");
    } else {
        printf("[-] Some tests failed.\n");
    }
    return overall_ok ? 0 : 1;
}