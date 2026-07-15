#include <stdio.h>
#include "data.h"  // sbox, Rcon, byte, word를 쓰기 위해 가져옴
#include <stdint.h>

#define Nb 4

// 함수 원형(Prototype) 선언
word RotWord(word w);
word SubWord(word w);
void KeyExpansion(byte key[], word w[], int Nk);
void AddRoundKey(byte state[16], word w[], int round);
void SubBytes(byte state[16]);


int main(){
	// AES를 만든 NIST 표준 문서(FIPS 197)에 나오는 공식 예제 키
	byte key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 
        0x09, 0xcf, 0x4f, 0x3c
    };
	// NIST 표준 예제 평문 사용 (plaintext, 16바이트 평문이 10번의 라운드를 거치며 암호문으로 바뀜)
	byte state[16] = {
        0x32, 0x43, 0xf6, 0xa8, 
        0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 
        0xe0, 0x37, 0x07, 0x34
    };

	// 확장된 라운드 키를 담을 빈 배열 준비
    // AES-128 기준: 4워드(Nb) * 11라운드(Nr+1) = 총 44워드 필요
	// 우선은 AES-128 기준으로 작성하고 전체 로직 구성 후 AES-256 지원하도록 스케일업
    word w[44];

    // 3. 키 확장 함수 실행! (Nk = 4)
    KeyExpansion(key, w, 4);

    AddRoundKey(state, w, 0);	
		
}


// RotWord(word w) 함수는 값을 하나 받아서 위치를 섞은 후 새로운 word 값을 return 하기에 함수 앞에 word
// 아무것도 return 하지 않으면 void
word RotWord(word w){ 
	// 역할: 위치 섞기 (Diffusion), 바이트들의 위치를 계속 바꿔주면서 키의 패턴이 한 곳에 머물지 않고 퍼지게 만듦
	// 동작: 4바이트(1워드) 배열이 있을 때, left circular shift
	// 1. 왼쪽으로 1바이트 이동
	// 2. 오른쪽으로 3바이트 이동
	// 3, 두 결과를 or 연산하여 합침
	// => left circular shift
	return (w << 8) | (w >>24);
}

word SubWord(word w){
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

void KeyExpansion(byte key[], word w[], int Nk){
	// 역할: 기존의 키 길이를 늘려 라운드 키 제작 -> 원본키를 유추할 수 없도록 안전한 새 키를 만듦
	int Nr;
	if (Nk == 4) {
		Nr = 10;		// AES-128 bit
	} else{ 
		if (Nk == 8) Nr = 14;  // AES-256 bit
	}

	word temp;
	int i = 0;
	
	while(i < Nk) {
		w[i] = ((word)key[4*i]     << 24) |
       		   ((word)key[4*i + 1] << 16) |
       		   ((word)key[4*i + 2] << 8)  |
       	 	   ((word)key[4*i + 3]);
		i = i + 1;
	}
	
	i = Nk;
	
	while(i < Nb * (Nr+1)) {
		temp = w[i-1];
		if (i % Nk == 0){
			temp = SubWord(RotWord(temp)) ^ ((word)Rcon[i/Nk] << 24);
		} else if(Nk > 6 & i % Nk == 4){
			temp = SubWord(temp);
		}
		w[i] = w[i-Nk] ^ temp;
		i = i + 1;
	}
}

// 매개변수에서 함수 선언 int round 스코프에서 해줄 필요 없지
void AddRoundKey(byte state[16], word w[], int round){
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

void SubBytes(byte state[16]){
	// 역할: 비선형 변환, 패턴 파괴)
	// 동작: state의 한 바이트를 sbox 테이블과 비교하여 1:1 치환
	for (int i = 0; i < 16; i++) state[i] = sbox[state[i]];
}

void MixColumns(byte state[16]){

}