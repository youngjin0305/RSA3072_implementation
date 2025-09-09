// 대상 테스트 벡터 파일 : 
// RSAES_(3072)(3)(SHA256)_DET.txt
// RSAES_(3072)(3)(SHA256)_ENT.txt

// 1. 컴파일 : gcc testVector.c -o testVector -lcrypto
// 2. 실행 : testVector 
//   * 자동으로 같은 경로 내에 있는 해당 테스트 벡터 파일 읽어드림 -> 테스트 결과 터미널 출력
//   * 해당 부분은 내일 오전에 파일 이름을 인수로 입력 받도록 수정 (예정)


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define LINE_MAX 8192

// --- Utility: trim newline / spaces on right
static void rtrim(char *s) {
    int i = (int)strlen(s) - 1;
    while (i >= 0 && (s[i] == '\n' || s[i] == '\r' || s[i] == ' ' || s[i] == '\t')) {
        s[i] = '\0'; i--;
    }
}

// --- hex string -> bytes (allocates buffer)
// returns pointer (must free) or NULL on error. out_len set to length in bytes.
static uint8_t* hex_to_bytes_alloc(const char *hex, size_t *out_len) {
    if (!hex) return NULL;
    // skip leading spaces
    while (*hex == ' ' || *hex == '\t') hex++;
    size_t hexlen = strlen(hex);
    while (hexlen > 0 && (isspace(hex[hexlen - 1]))) hexlen--;
    if (hexlen % 2 != 0) return NULL;
    size_t len = hexlen / 2;
    uint8_t *buf = malloc(len);
    if (!buf) return NULL;
    for (size_t i = 0; i < len; i++) {
        unsigned int v;
        if (sscanf(hex + 2*i, "%2x", &v) != 1) { free(buf); return NULL; }
        buf[i] = (uint8_t)v;
    }
    *out_len = len;
    return buf;
}

// --- hex -> BIGNUM
static BIGNUM* hex_to_bignum(const char *hex) {
    if (!hex) return NULL;
    // copy and trim
    char *tmp = strdup(hex);
    if (!tmp) return NULL;
    rtrim(tmp);
    // remove optional 0x prefix
    if (tmp[0]=='0' && (tmp[1]=='x' || tmp[1]=='X')) memmove(tmp, tmp+2, strlen(tmp+2)+1);
    BIGNUM *bn = NULL;
    if (BN_hex2bn(&bn, tmp) == 0) {
        free(tmp);
        return NULL;
    }
    free(tmp);
    return bn;
}

// --- MGF1 (from seed -> mask), using EVP digest (SHA-256)
static int mgf1(const unsigned char *seed, size_t seedlen, unsigned char *mask, size_t masklen, const EVP_MD *md) {
    unsigned char counter_be[4];
    uint32_t counter = 0;
    size_t hlen = (size_t)EVP_MD_size(md);
    unsigned char digest[EVP_MAX_MD_SIZE];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;

    size_t generated = 0;
    while (generated < masklen) {
        // counter to 4-byte big-endian
        counter_be[0] = (unsigned char)((counter >> 24) & 0xFF);
        counter_be[1] = (unsigned char)((counter >> 16) & 0xFF);
        counter_be[2] = (unsigned char)((counter >> 8) & 0xFF);
        counter_be[3] = (unsigned char)(counter & 0xFF);

        if (EVP_DigestInit_ex(ctx, md, NULL) != 1) { EVP_MD_CTX_free(ctx); return 0; }
        if (EVP_DigestUpdate(ctx, seed, seedlen) != 1) { EVP_MD_CTX_free(ctx); return 0; }
        if (EVP_DigestUpdate(ctx, counter_be, 4) != 1) { EVP_MD_CTX_free(ctx); return 0; }
        unsigned int outlen = 0;
        if (EVP_DigestFinal_ex(ctx, digest, &outlen) != 1) { EVP_MD_CTX_free(ctx); return 0; }

        size_t to_copy = (generated + outlen <= masklen) ? outlen : (masklen - generated);
        memcpy(mask + generated, digest, to_copy);
        generated += to_copy;
        counter++;
    }

    EVP_MD_CTX_free(ctx);
    return 1;
}

// --- OAEP encode with explicit seed (SHA-256, MGF1-SHA256)
// Implements EME-OAEP as RFC8017 but allows deterministic seed input.
// Parameters:
//  - msg, msglen: message bytes
//  - seed, seedlen: seed for OAEP (should be hLen bytes)
//  - k: target encoded message length (RSA modulus length in bytes)
//  - md: hash function (EVP_sha256())
// Output:
//  - out (length k) must be allocated by caller.
// Returns 1 on success, 0 on error.
static int oaep_encode_with_seed(const unsigned char *msg, size_t msglen,
                                 const unsigned char *seed, size_t seedlen,
                                 unsigned char *out, size_t k,
                                 const EVP_MD *md) {
    size_t hLen = (size_t)EVP_MD_size(md);
    if (k < 2*hLen + 2) return 0; // message too long
    if (seedlen != hLen) return 0;

    // lHash = Hash(label), label is empty -> hash of empty string
    unsigned char lHash[EVP_MAX_MD_SIZE];
    unsigned int lHash_len = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;
    if (EVP_DigestInit_ex(ctx, md, NULL) != 1) { EVP_MD_CTX_free(ctx); return 0; }
    if (EVP_DigestUpdate(ctx, "", 0) != 1) { EVP_MD_CTX_free(ctx); return 0; }
    if (EVP_DigestFinal_ex(ctx, lHash, &lHash_len) != 1) { EVP_MD_CTX_free(ctx); return 0; }
    EVP_MD_CTX_free(ctx);

    size_t ps_len = k - msglen - 2*hLen - 2;
    // DB = lHash || PS || 0x01 || M
    unsigned char *DB = malloc(hLen + ps_len + 1 + msglen);
    if (!DB) return 0;
    unsigned char *p = DB;
    memcpy(p, lHash, hLen); p += hLen;
    if (ps_len > 0) memset(p, 0x00, ps_len);
    p += ps_len;
    *p++ = 0x01;
    memcpy(p, msg, msglen);

    size_t db_len = hLen + ps_len + 1 + msglen;
    // seed MUST be hLen
    unsigned char *dbMask = malloc(db_len);
    if (!dbMask) { free(DB); return 0; }
    if (!mgf1(seed, seedlen, dbMask, db_len, md)) { free(DB); free(dbMask); return 0; }

    unsigned char *maskedDB = malloc(db_len);
    if (!maskedDB) { free(DB); free(dbMask); return 0; }
    for (size_t i = 0; i < db_len; i++) maskedDB[i] = DB[i] ^ dbMask[i];

    unsigned char *seedMask = malloc(hLen);
    if (!seedMask) { free(DB); free(dbMask); free(maskedDB); return 0; }
    if (!mgf1(maskedDB, db_len, seedMask, hLen, md)) { free(DB); free(dbMask); free(maskedDB); free(seedMask); return 0; }

    unsigned char *maskedSeed = malloc(hLen);
    if (!maskedSeed) { free(DB); free(dbMask); free(maskedDB); free(seedMask); return 0; }
    for (size_t i = 0; i < hLen; i++) maskedSeed[i] = seed[i] ^ seedMask[i];

    // EM = 0x00 || maskedSeed || maskedDB  (total length k)
    size_t idx = 0;
    out[idx++] = 0x00;
    memcpy(out + idx, maskedSeed, hLen); idx += hLen;
    memcpy(out + idx, maskedDB, db_len); idx += db_len;

    // cleanup
    free(DB); free(dbMask); free(maskedDB); free(seedMask); free(maskedSeed);
    // idx should equal k
    return (idx == k) ? 1 : 0;
}

// --- RSA raw encrypt (no padding): computes c = EM^e mod n
// We call RSA_public_encrypt(..., RSA_NO_PADDING) after creating RSA with n,e.
static int rsa_raw_encrypt_with_EM(RSA *rsa, const unsigned char *EM, size_t em_len, unsigned char *out, size_t out_len) {
    int rsa_sz = RSA_size(rsa);
    if ((size_t)rsa_sz != out_len) return 0;
    if (em_len != (size_t)rsa_sz) return 0;
    // RSA_public_encrypt with NO_PADDING expects a big-endian integer in EM of size rsa_sz
    int res = RSA_public_encrypt((int)em_len, EM, out, rsa, RSA_NO_PADDING);
    if (res != rsa_sz) return 0;
    return 1;
}

// --- perform one test: construct RSA from n,e, OAEP-encode with seed, raw encrypt and compare with expected ct.
static int perform_rsa_oaep_test(const char *count_str, const char *mod_hex, const char *exp_hex,
                                 const char *pt_hex, const char *seed_hex, const char *ct_hex) {
    int ok = 0;
    // parse BN
    BIGNUM *bn_n = hex_to_bignum(mod_hex);
    BIGNUM *bn_e = hex_to_bignum(exp_hex);
    if (!bn_n || !bn_e) {
        fprintf(stderr, "[!] Test %s: invalid n/e\n", count_str);
        BN_free(bn_n); BN_free(bn_e);
        return 0;
    }

    // parse plaintext, seed, ciphertext -> bytes
    size_t pt_len = 0, seed_len = 0, ct_len = 0;
    uint8_t *pt = hex_to_bytes_alloc(pt_hex, &pt_len);
    uint8_t *seed = hex_to_bytes_alloc(seed_hex, &seed_len);
    uint8_t *ct = hex_to_bytes_alloc(ct_hex, &ct_len);
    if (!pt || !seed || !ct) {
        fprintf(stderr, "[!] Test %s: hex parse failed (pt/seed/ct)\n", count_str);
        BN_free(bn_n); BN_free(bn_e);
        free(pt); free(seed); free(ct);
        return 0;
    }

    // create RSA and set n,e
    RSA *rsa = RSA_new();
    if (!rsa) goto cleanup;
    BIGNUM *n_dup = BN_dup(bn_n);
    BIGNUM *e_dup = BN_dup(bn_e);
    if (!n_dup || !e_dup) goto cleanup;
    if (RSA_set0_key(rsa, n_dup, e_dup, NULL) != 1) goto cleanup;
    // Now rsa owns n_dup,e_dup

    int k = RSA_size(rsa); // modulus length in bytes
    if (ct_len < (size_t)k) {
        // left-pad expected ciphertext with zeros if vector omitted leading zeros
        uint8_t *ct_full = calloc(1, k);
        if (!ct_full) goto cleanup;
        memcpy(ct_full + (k - ct_len), ct, ct_len);
        free(ct);
        ct = ct_full;
        ct_len = k;
    } else if (ct_len > (size_t)k) {
        fprintf(stderr, "[!] Test %s: ciphertext longer than modulus\n", count_str);
        goto cleanup;
    }

    // OAEP parameters
    const EVP_MD *md = EVP_sha256();
    size_t hLen = (size_t)EVP_MD_size(md);
    if ((size_t)k < 2*hLen + 2) {
        fprintf(stderr, "[!] Test %s: modulus too small for OAEP-SHA256\n", count_str);
        goto cleanup;
    }
    if (seed_len != hLen) {
        fprintf(stderr, "[!] Test %s: seed length (%zu) != hLen (%zu)\n", count_str, seed_len, hLen);
        goto cleanup;
    }
    // check pt length allowable
    size_t max_msg = k - 2*hLen - 2;
    if (pt_len > max_msg) {
        fprintf(stderr, "[!] Test %s: plaintext too long for OAEP-SHA256 on this modulus\n", count_str);
        goto cleanup;
    }

    // build EM
    unsigned char *EM = malloc(k);
    if (!EM) goto cleanup;
    if (!oaep_encode_with_seed(pt, pt_len, seed, seed_len, EM, (size_t)k, md)) {
        fprintf(stderr, "[!] Test %s: OAEP encode failed\n", count_str);
        free(EM); goto cleanup;
    }

    // raw RSA encrypt EM
    unsigned char *out = malloc(k);
    if (!out) { free(EM); goto cleanup; }
    if (!rsa_raw_encrypt_with_EM(rsa, EM, k, out, k)) {
        fprintf(stderr, "[!] Test %s: RSA raw encrypt failed\n", count_str);
        free(EM); free(out); goto cleanup;
    }

    // compare out with expected ct
    if (memcmp(out, ct, k) == 0) {
        ok = 1;
        // printf("[+] Test %s OK\n", count_str);
    } else {
        fprintf(stdout, "[!] Test %s FAILED\n", count_str);
        // print debug hex snippets
        fprintf(stdout, "- Modulus bytes: %d\n", k);
        fprintf(stdout, "- Plaintext hex: %s\n", pt_hex);
        fprintf(stdout, "- Seed hex: %s\n", seed_hex);
        fprintf(stdout, "- Expected CT (first 64 hex): ");
        for (int i = 0; i < (k>32?32:k); i++) fprintf(stdout, "%02x", ct[i]);
        fprintf(stdout, "\n- Got CT (first 64 hex): ");
        for (int i = 0; i < (k>32?32:k); i++) fprintf(stdout, "%02x", out[i]);
        fprintf(stdout, "\n");
    }

    free(EM); free(out);

cleanup:
    RSA_free(rsa);
    BN_free(bn_n);
    BN_free(bn_e);
    free(pt); free(seed); free(ct);
    return ok;
}

// --- parse .rsp style vector file supporting fields:
// COUNT, MODULUS, EXPONENT, PLAINTEXT, SEED, CIPHERTEXT
static int check_vector_file(const char *fname) {
    FILE *fp = fopen(fname, "r");
    if (!fp) {
        fprintf(stderr, "no file %s\n", fname);
        return 0;
    }
    printf("testing \"%s\"\n", fname);

    char line[LINE_MAX];
    char count_str[128] = "1";
    char mod_hex[16384] = {0}, exp_hex[256] = {0}, pt_hex[8192] = {0}, seed_hex[256] = {0}, ct_hex[16384] = {0};
    int has_n = 0, has_e = 0, has_m = 0, has_seed = 0, has_c = 0;
    int all_ok = 1;
    int test_case_count = 1;

    while (fgets(line, sizeof(line), fp) != NULL) {
        // skip leading spaces
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        
        if (strncmp(p, "n = ", 4) == 0) {
            // start new case
            if (has_n || has_e || has_m || has_seed || has_c) {
                if (!perform_rsa_oaep_test(count_str, mod_hex, exp_hex, pt_hex, seed_hex, ct_hex)) {
                    all_ok = 0;
                }
                has_n=0; has_e=0; has_m=0; has_seed=0; has_c=0;
                test_case_count++;
                sprintf(count_str, "%d", test_case_count);
            }
            strncpy(mod_hex, p+4, sizeof(mod_hex)-1); rtrim(mod_hex);
            has_n = 1;
        } else if (strncmp(p, "e = ", 4) == 0) {
            strncpy(exp_hex, p+4, sizeof(exp_hex)-1); rtrim(exp_hex);
            has_e = 1;
        } else if (strncmp(p, "M = ", 4) == 0) {
            strncpy(pt_hex, p+4, sizeof(pt_hex)-1); rtrim(pt_hex);
            has_m = 1;
        } else if (strncmp(p, "Seed = ", 7) == 0) {
            strncpy(seed_hex, p+7, sizeof(seed_hex)-1); rtrim(seed_hex);
            has_seed = 1;
        } else if (strncmp(p, "C = ", 4) == 0) {
            strncpy(ct_hex, p+4, sizeof(ct_hex)-1); rtrim(ct_hex);
            has_c = 1;
        } else if (strncmp(p, "COUNT = ", 8) == 0) {
             // For files that contain COUNT, keep the original behavior
             // start new case
             if (has_n || has_e || has_m || has_seed || has_c) {
                if (!perform_rsa_oaep_test(count_str, mod_hex, exp_hex, pt_hex, seed_hex, ct_hex)) {
                    all_ok = 0;
                }
                has_n=0; has_e=0; has_m=0; has_seed=0; has_c=0;
             }
             strncpy(count_str, p+8, sizeof(count_str)-1);
             rtrim(count_str);
        } else if (strncmp(p, "MODULUS = ", 10) == 0) {
            strncpy(mod_hex, p+10, sizeof(mod_hex)-1); rtrim(mod_hex); has_n = 1;
        } else if (strncmp(p, "EXPONENT = ", 11) == 0) {
            strncpy(exp_hex, p+11, sizeof(exp_hex)-1); rtrim(exp_hex); has_e = 1;
        } else if (strncmp(p, "PLAINTEXT = ", 12) == 0 || strncmp(p, "MSG = ", 6) == 0) {
            if (strncmp(p, "PLAINTEXT = ", 12) == 0) strncpy(pt_hex, p+12, sizeof(pt_hex)-1);
            else strncpy(pt_hex, p+6, sizeof(pt_hex)-1);
            rtrim(pt_hex); has_m = 1;
        } else if (strncmp(p, "CIPHERTEXT = ", 13) == 0 || strncmp(p, "CT = ", 5) == 0) {
            if (strncmp(p, "CIPHERTEXT = ", 13) == 0) strncpy(ct_hex, p+13, sizeof(ct_hex)-1);
            else strncpy(ct_hex, p+5, sizeof(ct_hex)-1);
            rtrim(ct_hex); has_c = 1;
        } else {
            // ignore other lines or comments
        }
    }

    // check last case
    if (has_n || has_e || has_m || has_seed || has_c) {
        if (!perform_rsa_oaep_test(count_str, mod_hex, exp_hex, pt_hex, seed_hex, ct_hex)) {
            all_ok = 0;
        }
    }

    if (all_ok) printf("[+] test file %s: all cases passed\n", fname);
    else printf("[-] test file %s: some cases failed\n", fname);

    fclose(fp);
    return all_ok;
}

int main(int argc, char **argv) {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    int overall_ok = 1;
    if (argc < 2) {
        // No arguments given, test the user's files
        printf("No vector files specified. Defaulting to user-provided files:\n");
        if (!check_vector_file("RSAES_(3072)(3)(SHA256)_DET.txt")) overall_ok = 0;
        if (!check_vector_file("RSAES_(3072)(3)(SHA256)_ENT.txt")) overall_ok = 0;
    } else {
        // Arguments were given, test specified files
        for (int i = 1; i < argc; i++) {
            if (!check_vector_file(argv[i])) overall_ok = 0;
        }
    }

    if (overall_ok) printf("[+] all vector files passed\n");
    else printf("[-] some vector files failed\n");

    ERR_free_strings();
    EVP_cleanup();
    return overall_ok ? 0 : 2;
}