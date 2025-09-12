#include "rsa.h"
#include <stdbool.h>

int is_probably_prime(const Bignum* n, int k) {//k=64
    bool isprime=true; // 소수판별
    const Bignum zero={.limbs={0}, .size=0};
    const Bignum one={.limbs={1}, .size=1};
    const Bignum two={.limbs={2}, .size=1};
    const Bignum three={.limbs={3}, .size=1};
    Bignum q0, r0;
    //2의 배수이면 바로 0 반환
    bignum_init(&q0);
    bignum_init(&r0);
    bignum_divide(&q0, &r0, n, &two);
    if(bignum_compare(&r0, &zero)==0) return 0;

    for(int i=0; i<k; i++) {
        Bignum test_value;//n-1 값
        bignum_init(&test_value);
        bignum_subtract(&test_value,n,&one);
        Bignum result;
        bignum_init(&result);
        //1. 랜덤으로 2이상 n-2이하 임의의 정수
        unsigned char sudo[BIGNUM_ARRAY_SIZE*4]; //의사 난수 저장한 버퍼
        generate_secure_random(sudo, sizeof(sudo));
        Bignum sudo_number;
        bignum_init(&sudo_number);
        //버퍼 --> bignum
        size_t limbs = sizeof(sudo) / 4;
        if (limbs > BIGNUM_ARRAY_SIZE) limbs = BIGNUM_ARRAY_SIZE;

        for (size_t i = 0; i < limbs; i++) {
            sudo_number.limbs[i] =
                (uint32_t)sudo[4*i]
            | ((uint32_t)sudo[4*i+1] << 8)
            | ((uint32_t)sudo[4*i+2] << 16)
            | ((uint32_t)sudo[4*i+3] << 24);
        }
        sudo_number.size = (int)limbs;
        while (sudo_number.size > 0 && sudo_number.limbs[sudo_number.size - 1] == 0) {
            sudo_number.size--;
        }
        // 2 ≤ a ≤ n-2
        Bignum range, qa, ra;
        bignum_init(&range);
        bignum_init(&qa);
        bignum_init(&ra);

        bignum_subtract(&range, n, &three);
        bignum_divide(&qa, &ra, &sudo_number, &range);
        bignum_add(&sudo_number, &ra, &two);

        //2. n-1 = 2^k * d (d는 홀수)
        int s=0;
        Bignum rem; //나머지 값
        bignum_init(&rem);
        Bignum d; // n-1값?
        bignum_init(&d);
        bignum_copy(&d, &test_value);
        Bignum q;
        bignum_init(&q);
        while (1) {
            bignum_divide(&q, &rem, &d, &two);
            if (bignum_compare(&rem, &zero) != 0) break;
            bignum_copy(&d, &q);  
            s++;
        }
        
        //3. a^d mod n = 1 or n-1 n은 소수
        bignum_mod_exp(&result, &sudo_number, &d, n);
        if(bignum_compare(&result, &one)==0 || bignum_compare(&result, &test_value)==0) {
            continue;
        }

        //4. r을 0~k-1까지 증가 (a^(d*(2^r)) mod n이 n-1 인지 검사
        else {
            isprime=false;
            for (int r = 1; r < s; r++) {
                Bignum xx; //x^2
                bignum_init(&xx);
                bignum_multiply(&xx, &result, &result);

                Bignum qxxn;// xx/n의 몫
                bignum_init(&qxxn);
                bignum_divide(&qxxn, &result, &xx, n);

                if (bignum_compare(&result, &test_value) == 0) {
                    isprime = true;
                    break;
                }
            }
            if (!isprime) {
                return isprime; // 합성수
            }
        }
        //5. 만약 n-1이 한번이라도 나오면 n은 소수
        //6. 위의 모든 조건을 통과하지 못하면 n은 합성수
    }
    return isprime;
}


void generate_prime(Bignum* prime, int bits) {
    Bignum candidate;

    while (1) {
        bignum_init(&candidate);

        // 난수 생성에 필요한 바이트 수 계산
        int bytes = (bits + 7) / 8;
        unsigned char* buffer = (unsigned char*)malloc(bytes);
        if (buffer == NULL) continue;

        // 안전한 난수 생성
        if (generate_secure_random(buffer, bytes) != 0) {
            free(buffer);
            continue;
        }

        // 바이트를 Bignum으로 변환
        for (int i = 0; i < bytes; i++) {
            int limb_idx = i / 4; // 몇 번째 limb인지
            int byte_idx = i % 4; //그 limb 안에서 몇 번째 바이트 자리인지

            candidate.limbs[limb_idx] |= ((uint32_t)buffer[i]) << (byte_idx * 8);
            if (limb_idx >= candidate.size) {
                candidate.size = limb_idx + 1;
            }
        }

        free(buffer);

        // 최상위 비트를 1로 설정(비트 크기 보장)
        int msb_limb = (bits - 1) / 32;
        int msb_bit = (bits - 1) % 32;
        candidate.limbs[msb_limb] |= (1 << msb_bit);
        if (msb_limb >= candidate.size) {
            candidate.size = msb_limb + 1;
        }

        // 최하위 비트를 1로 설정(홀수 보장)
        candidate.limbs[0] |= 1;

        // 밀러-라빈 테스트로 소수인지 확인
        if (is_probably_prime(&candidate, MILLER_RABIN_ROUNDS)) {
            bignum_copy(prime, &candidate);
            return;
        }
    }
}
