#include <stdio.h>
#include <stdint.h>
#include "data.h"  // sbox, Rcon, byte, word를 쓰기 위해 가져옴

#define Nb 4

// 함수 원형(Prototype) 선언
word RotWord(word w);
word SubWord(word w);
void KeyExpansion(const byte key[], word w[], int Nk, int Nr);
void AddRoundKey(byte state[16], word w[], int round);
void SubBytes(byte state[16]);
void MixColumns(byte state[16]);
void ShiftRows(byte state[16]);

void AES_Encrypt(const byte plainText[16], const byte key[16], int keyLength, byte cipherText[16]) {
	int Nk, Nr;
	
	if (keyLength == 128) {
		Nk = 4;
		Nr = 10;
	} else if (keyLength == 256) {
		Nk = 8;
		Nr = 14;
	} else {
		printf("Unsupported AES key length");
		return; // 쓰레기값 연산 방지(Early Return)
	}

	// 입력 평문 사용
	byte state[16];
	for (int i = 0; i < 16; i++) {
		state[i] = plainText[i];
	}

    // AES-256 최대 워드 수(60개) 기준 할당
	word w[60];

    // 키 확장
    KeyExpansion(key, w, Nk, Nr);

	// [Pre-Round] Round 0
    AddRoundKey(state, w, 0);	
	
	// [Main Round] Round 1 ~ (Nr - 1)
	for (int round = 1; round < Nr; round++){ // 0 라운드 했으니 1 라운드부터 
		SubBytes(state); 
		ShiftRows(state);
		MixColumns(state);
		AddRoundKey(state, w, round);
	}
	
	// [Final Round] Round Nr
	SubBytes(state);
	ShiftRows(state);
	AddRoundKey(state, w, Nr);

	// 최종 결과를 출력 배열에 복사
	for (int i = 0; i < 16; i++) {
		cipherText[i] = state[i];
	}
}

// RotWord(word w) 함수는 값을 하나 받아서 위치를 섞은 후 새로운 word 값을 return 하기에 함수 앞에 word
// 아무것도 return 하지 않으면 void
word RotWord(word w) { 
	// 역할: 위치 섞기 (Diffusion), 바이트들의 위치를 계속 바꿔주면서 키의 패턴이 한 곳에 머물지 않고 퍼지게 만듦
	// 동작: 4바이트(1워드) 배열이 있을 때, left circular shift
	// 1. 왼쪽으로 1바이트 이동
	// 2. 오른쪽으로 3바이트 이동
	// 3, 두 결과를 or 연산하여 합침
	// => left circular shift
	return (w << 8) | (w >>24);
}

word SubWord(word w) {
	// 역할: 각 바이트에 S-box 적용, 비선형성 추가하여 암호 단단하게
	// 동작: S-box라는 룩업 테이블 참조하여 입력된 1바이트를 완전히 다른 1바이트로 1:1 교체
	// 비트 마스킹 & 0xff, & == AND, | == OR
	// (word)는 type casting(형변환)인데, (바꿀자료형)값 형태로 변수의 크기나 성질을 바꿔줌
	// sbox는 1바이트 크기라서 쉬프트 연산자 그대로 쓰면 값이 0x63 >> 24 -> 0x00 되버림
	// (word)는 0x11223344로 공간을 넓혀주니까 0x63 >> 24 -> 0x00000063으로 값이 남아있음
	word result = 0;
	result |= (word)sbox[(w >> 24) & 0xff] << 24;
	result |= (word)sbox[(w >> 16) & 0xff] << 16;
	result |= (word)sbox[(w >>  8) & 0xff] <<  8;
	result |= (word)sbox[ w        & 0xff];
	return result;
}

void KeyExpansion(const byte key[], word w[], int Nk, int Nr) {
	// 역할: 기존의 키 길이를 늘려 라운드 키 제작 -> 원본키를 유추할 수 없도록 안전한 새 키를 만듦
	word temp;

	// Nb(블록 크기)는 AES 표준에서 항상 4워드(16바이트)로 고정
	int totalWords = (Nr + 1) * Nb;
	
	// 첫 Nk개의 워드는 원본 키에서 그대로 복사
	// AES-128이면 4번(16바이트), AES-256이면 8번(32바이트) 반복
	for (int i = 0; i < Nk; i++) {
		w[i] = ((word)key[4*i]     << 24) |
       		   ((word)key[4*i + 1] << 16) |
       		   ((word)key[4*i + 2] << 8)  |
       	 	   ((word)key[4*i + 3]);
	}
	
	// 나머지 라운드 키 생성
	for (int i = Nk; i < totalWords; i++) {
		temp = w[i-1]; // 직전 word
		
		// 인덱스가 Nk의 배수일 때
		if (i % Nk == 0) {
			temp = SubWord(RotWord(temp)) ^ ((word)Rcon[i / Nk] << 24);
		}
		// AES-256
		else if (Nk > 6 && i % Nk == 4) {
			temp = SubWord(temp); // 추가로 SubWord 연산을 한 번 더 거쳐 비선형성 극대화
		}
		// 최종적으로 Nk 번째 앞의 워드와 연산하여 현재 워드 완성
		w[i] = w[i- Nk] ^ temp;
	}
}

// 매개변수에서 함수 선언 int round 스코프에서 해줄 필요 없지
void AddRoundKey(byte state[16], word w[], int round) {
	// 역할: 공격자로 하여금 원본 데이터를 복구할 수 없도록 비밀키 사용
	// 동작: 16바이트의 state와 16바이트의 RoundKey(w)를 같은 인덱스끼리 1:1 XOR 연산
	for(int c = 0; c < 4; c++){
		// 이번 라운드에 해당하는 word 1개 꺼내오기
		// 0라운드 -> w[0~3], 1라운드 -> w[4~7]
		word k = w[round * 4 + c];

		// word를 4개의 바이트로 쪼개서
		state[c * 4 + 0] ^= (k >> 24) & 0xFF; // 가장 앞 바이트
		state[c * 4 + 1] ^= (k >> 16) & 0xFF; // 두 번째 바이트
		state[c * 4 + 2] ^= (k >>  8) & 0xFF; // 세 번째 바이트
		state[c * 4 + 3] ^=  k        & 0xFF; // 네 번째 바이트
	}
}

void SubBytes(byte state[16]) {
	// 역할: 비선형 변환, 패턴 파괴)
	// 동작: state의 한 바이트를 sbox 테이블과 비교하여 1:1 치환
	for (int i = 0; i < 16; i++) state[i] = sbox[state[i]];
}

// static inline을 붙이면 컴파일러가 호출 오버헤드를 완전히 없애고 코드를 박아넣어 줌
// 매크로/인라인 함수: 가독성을 위해 소스 코드에는 함수처럼 작성하되, 실제 컴파일할 떄 내부 계산 식으로 바꾸어 달라고 지시하는 것
// 일반 함수: 프로그램 실행 중에 gf_mul 주소로 점프했다가 연산 후 복귀
// 인라인/매크로 함수: 컴파일러가 함수 호출 부분을 실제 함수 본체 코드로 치환

static inline byte mul1(byte x) {
    return x; 
}

// mul2는 AES 표준 문서에 명시되어 있는 고유 연산인 xtime입니다. 다른 경우에 수에 따른 함수가 mul1, mul3이라 mul2로 표기하였습니다.
static inline byte mul2(byte x) {
    return (x & 0x80) ? ((x << 1) ^ 0x1B) : (x << 1);
}
// 0x80: 1000 0000 (MSB만 남김), 0x는 16진수임을 나타내는 prefix, 80은 16진수
// 0x0F: 0000 1111 (하위 4비트만 남김)
// 0xF0: 1111 0000 (상위 4비트만 남김)

static inline byte mul3(byte x) {
    return mul2(x) ^ x;
}

/*
 * [MixColumns 행렬 곱셈 원리]
 * 아래 연산은 AES 공식 문서에 정의된 다음의 MDS 행렬을 열(Column) 벡터에 곱하는 과정입니다.
 * | 02 03 01 01 |   | temp[0] |
 * | 01 02 03 01 | * | temp[1] |
 * | 01 01 02 03 |   | temp[2] |
 * | 03 01 01 02 |   | temp[3] |
 */

void MixColumns(byte state[16]) {
	// 역할: 각 열에 대해 MDS 행렬을 곱하여 확산 효과 극대화
	// 동작: 열 단위로 데이터를 뽑아 GF(2^8) 상의 선형 변환 수행
    byte temp[4]; // 한 열의 값을 잠시 담아둘 공간
    byte result[4]; // 연산 결과를 담을 공간

    // state의 각 열을 가져와서
    for (int col = 0; col < 4; col++) {
        // state의 한 열을 1차원 배열로 보고 temp의 각 인덱스에 복사
        // col=0이면 state[0,1,2,3], col=1이면 state[4,5,6,7]
        for (int i = 0; i < 4; i++) {
            temp[i] = state[col * 4 + i];
        }

        // 2) temp와 고정 행렬의 동일 인덱스끼리 계산
		result[0] = mul2(temp[0]) ^ mul3(temp[1]) ^ mul1(temp[2]) ^ mul1(temp[3]);
        result[1] = mul1(temp[0]) ^ mul2(temp[1]) ^ mul3(temp[2]) ^ mul1(temp[3]);
        result[2] = mul1(temp[0]) ^ mul1(temp[1]) ^ mul2(temp[2]) ^ mul3(temp[3]);
        result[3] = mul3(temp[0]) ^ mul1(temp[1]) ^ mul1(temp[2]) ^ mul2(temp[3]);
		
        // 3. 연산 결과를 다시 state에 반영
        for (int i = 0; i < 4; i++) {
            state[col * 4 + i] = result[i];
        }
	}
}

void ShiftRows(byte state[16]) {
	// 역할: 행 위치를 shift해서 한 열의 데이터가 서로 다른 열로 흩어지도록 함, 재배치
	// 동작: 각 행을 왼쪽으로 일정 칸수만큼 순환 이동
	byte temp[16];

	for (int i = 0; i < 16; i++ ) temp[i] = state[i];
	
	// 0행 (인덱스: 0, 4, 8, 12) -> 0칸 이동 (생략 또는 자기 자신 덮어쓰기)
    
    // 1행 (인덱스: 1, 5, 9, 13) -> 왼쪽 1칸 순환 이동
    state[1] = temp[5]; state[5] = temp[9]; state[9] = temp[13]; state[13] = temp[1];
    
    // 2행 (인덱스: 2, 6, 10, 14) -> 왼쪽 2칸 순환 이동
    state[2] = temp[10]; state[6] = temp[14]; state[10] = temp[2]; state[14] = temp[6];
    
    // 3행 (인덱스: 3, 7, 11, 15) -> 왼쪽 3칸 순환 이동
    state[3] = temp[15]; state[7] = temp[3]; state[11] = temp[7]; state[15] = temp[11];
}