// 헤더파일의 중복방지
#ifndef DATA_H // if not define -> 매크로 정의 (#endif까지 컴파일))
#define DATA_H // 매크로 정의, 재정의 오류 방지

#include <stdint.h>

// 전역 범위에서 byte와 word를 미리 정의, 명시적으로 나타냄
typedef uint8_t byte;   // 1바이트
typedef uint32_t word;  // 4바이트

// 외부변수 (외부에 있는 변수를 사용하겠다)
extern const byte sbox[256];
extern const byte Rcon[11];

#endif // 조건부 컴파일 블록이 끝남을 명시

// 해더파일에 extern을 사용해서 외부(data.c)에 배열이 있음을 명시해둠
// AES.c에서 include하여 사용함