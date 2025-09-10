#include "rsa.h"
#include <stdio.h>
#include <stddef.h>
#include <windows.h>
#include <bcrypt.h>
#include <stddef.h>
#pragma comment(lib, "bcrypt.lib")

int generate_secure_random(unsigned char* buffer, size_t size) {
    // 출력 버퍼가 없거나 길이가 0이면 -1 호출
    if (buffer == NULL || size == 0) {
        return -1;
    }

    // 현재 버퍼 내 위치
    unsigned char* p = buffer;
    // 아직 채워야 할 바이트 수
    size_t remaining = size;
    size_t filled = 0;

    // 청크 최대 크기
    const ULONG MAX_CHUNK = 1u << 20;

    // 1MiB 단위로 잘라서 호출
    while (remaining > 0) {
        ULONG chunk = (remaining > MAX_CHUNK)
            ? MAX_CHUNK
            : (ULONG)remaining;
    // 남은 바이트가 있다면 청크 계산, 그 크기를 1MiB와 비교
        NTSTATUS st = BCryptGenRandom(
            //hAlgorithm
            NULL,
            //pbBuffer
            p,
            //cbBuffer
            chunk,
            //dwFlags
            BCRYPT_USE_SYSTEM_PREFERRED_RNG
        );

        // 난수 생성 호출, Windows가 선택한 시스템을 선택
        // 결과는 p부터 chunk 바이트에 직접 채워짐
        
        // 오류 처리, 난수 생성이 잘못되면 앞 바이트 의심
        // 그래서 0으로 덮어쓴 후 -2 반환
        if (!BCRYPT_SUCCESS(st)) {
            SecureZeroMemory(buffer, filled);
            return -2;
        }
        // 성공 시 포인터/카운터를 갱신, 남은 양 0될때까지 반복
        p += chunk;
        remaining -= chunk;
        filled += chunk;
    }

    return 0;
}

// 난수 생성
// 유틸 함수
    // 필요한 길이만큼 읽어옴
int random_3072_candidate(unsigned char out384[384]) {
    //84바이트(=3072비트) 난수 채우기
    int rc = generate_secure_random(out384, 384);
    if (rc != 0) return rc;
    out384[0] |= 0x80; // MSB=1 → 정확히 3072-bit
    out384[383] |= 0x01; // LSB=1 → 홀수화
    return 0;
}

// 필요한 길이만큼 OS CSPRNG에서 바이트를 읽어 옴
int random_oaep_seed32(unsigned char out[32]) { return generate_secure_random(out, 32); }

// 바이트 배열을 읽기 좋은 16진수로 출력
static void hexdump(const unsigned char* p, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        printf("%02X", p[i]);
        if ((i + 1) % 16 == 0) puts("");
        else if ((i + 1) % 2 == 0) putchar(' ');
    }
    if (n % 16) puts("");
}
