#pragma once

#include "rsa.h"

// RSA-OAEP 패딩 함수를 위한 외부 선언
// 원본 메시지를 OAEP 규칙에 맞게 패딩하여 암호화에 사용할 메시지 블록(EM)을 생성합니다.

// out: 패딩된 메시지(EM)를 저장할 버퍼
// msg: 원본 메시지
// msg_len: 원본 메시지 길이 (바이트)
// k: RSA 모듈러스 길이 (바이트)
// seed: OAEP에 사용될 시드(SHA256 해시 길이인 32바이트여야 함)

int rsa_oaep_pad(unsigned char* out, const unsigned char* msg, size_t msg_len, size_t k, const unsigned char* seed);