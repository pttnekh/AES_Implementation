#include<stdio.h>
#include<stdint.h>
#include "data.h"

// 모듈화된 AES_Encrypt 함수 원형
void AES_Encrypt(const byte plainText[16], const byte key[], int keyLength, byte cipherText[16]);

// 바이트 배열을 보기 좋게 16진수(Hex)로 출력해 주는 헬퍼 함수
void printHex(const char* label, const byte* data, int length) {
    printf("%s: ", label);
    for (int i = 0; i < length; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

int main() {
    // NIST 표준 문서 기준 평문 예제 (16바이트)
    byte plainText[16] = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    };
    
    // 암호문이 저장될 빈 배열
    byte cipherText[16];

    // [1] AES-128 테스트 (16바이트 키)
    byte key128[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    printf("=== AES-128 Encryption ===\n");
    AES_Encrypt(plainText, key128, 128, cipherText);
    printHex("Plaintext ", plainText, 16);
    printHex("Key (128) ", key128, 16);
    printHex("Ciphertext", cipherText, 16);
    printf("\n");

    // [2] AES-256 테스트 (32바이트 키)
    byte key256[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };

    printf("=== AES-256 Encryption ===\n");
    AES_Encrypt(plainText, key256, 256, cipherText);
    printHex("Plaintext ", plainText, 16);
    printHex("Key (256) ", key256, 32);
    printHex("Ciphertext", cipherText, 16);
    printf("\n");

    return 0;
}