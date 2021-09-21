#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include "openssl/applink.c" 

#define NUM_BYTES_READ_TXT 32 // 텍스트 파일에서 32바이트(256bit)씩 암호화 할 것이다.

int Cryptology(const unsigned char *cecret_key, const unsigned char *iv, FILE *ifp, FILE *ofp, int isEncrypt);

int main() {

	printf("AES 알고리즘(키 128bit)으로 암/복호화를 시작 합니다.");

	const EVP_CIPHER *algorism = EVP_aes_128_cbc(); //암호화에 사용될 알고리즘과 모드 생성
	EVP_CIPHER_CTX *ctx_enc = EVP_CIPHER_CTX_new(); //암호화 컨텍스트, AES의 10round(128bit) 동안 암호화 중간 데이터(알고리즘, 키, IV, 패딩 등) 저장할 컨텍스트 생성

	if (ctx_enc == NULL) {
		printf("암호화 컨텍스트가 생성되지 않았습니다.\n");
		return -1;
	}

	// 사용될 암호화 알고리즘을 ctx_enc에 잠시 저장하여 초기화, 암호화 알고리즘만 초기화 하기에 3~5값은 널로 지정함
	if (!(EVP_EncryptInit_ex(ctx_enc, algorism, NULL, NULL, NULL))) {
		printf("암호화에 사용될 알고리즘 초기화에 실패 하였습니다.\n");
		return -1;
	}

	printf("\n");
	printf("랜덤 비밀키와 랜덤 IV 바이트가 초기화 되었습니다.\n");
	printf("\n");

	//ctx_enc는 사용될 암호화 알고리즘을 저장하고 있다.
	unsigned char *cecret_key = (unsigned char*)malloc(EVP_CIPHER_CTX_key_length(ctx_enc));//AES 알고리즘에 사용될 비밀키 공간 동적 할당
	unsigned char *iv = (unsigned char*)malloc(EVP_CIPHER_CTX_iv_length(ctx_enc)); //IV, 평문의 첫 블록과 xor 연산하여 암호화를 시킬 값의 공간 동적 할당

	// 비밀키에 AES의 라운드 길이 만큼 난수를 넣어라 (128비트이니 10라운드)
	if (!RAND_bytes(cecret_key, EVP_CIPHER_CTX_key_length(ctx_enc))) {
		printf("비밀키에 난수 생성 실패 하였습니다.\n");
		return -1;
	}

	// IV에 AES의 라운드 길이 만큼 난수를 넣어라 (128비트이니 10라운드)
	if (!RAND_bytes(iv, EVP_CIPHER_CTX_iv_length(ctx_enc))) {
		printf("IV에 난수 생성 실패 하였습니다.\n");
		return -1;
	}

	printf("사용될 비밀키 값 : ");
	for (int i = 0; i < (int)strlen((const char*)cecret_key); i++)          //난수 비밀키 값 출력
		printf("0x%X ", cecret_key[i]);
	printf("\n");

	printf("사용될 IV 값 : ");
	for (int i = 0; i < (int)strlen((const char*)iv); i++)          //난수 IV값 출력
		printf("0x%X ", iv[i]);
	printf("\n");


	printf("\n");
	printf("평문 텍스트 파일을 읽어 암호화를 시작합니다.\n");
	printf("\n");

	FILE *pfp = fopen("C:/Users/LJS/Desktop/Computer Science/Information Security/평문.txt", "r");
	FILE *cfp = fopen("C:/Users/LJS/Desktop/Computer Science/Information Security/AES_암호문.txt", "w");


	if (pfp == NULL) {
		printf("평문 텍스트 파일이 존재하지 않습니다.\n");
		return -1;
	}

	if (cfp == NULL) {
		printf("암호문 텍스트 파일 생성에 실패 하였습니다.\n");
		return -1;
	}

	Cryptology(cecret_key, iv, pfp, cfp, 1); //암호화, 맨 오른쪽 1은 암호화 하겠다는 의미이다.
	//오른쪽 마지막 매개변수는 isEncrypt인데 1이면 암호화 0이면 복호화

	fclose(pfp);
	fclose(cfp);

	printf("\n");
	printf("암호문 텍스트 파일을 읽어 복호화를 시작합니다.\n");
	printf("\n");

	cfp = fopen("C:/Users/LJS/Desktop/Computer Science/Information Security/AES_암호문.txt", "r");
	pfp = fopen("C:/Users/LJS/Desktop/Computer Science/Information Security/AES_복호문.txt", "w");


	if (cfp == NULL) {
		printf("암호화된 텍스트 파일이 존재하지 않습니다.\n");
		return -1;
	}

	if (pfp == NULL) {
		printf("복호화 하여 평문을 만들 텍스트 파일 생성에 실패 하였습니다.\n");
		return -1;
	}

	Cryptology(cecret_key, iv, cfp, pfp, 0); //복호화

	fclose(cfp);
	fclose(pfp);

	return 0;
}

int Cryptology(const unsigned char *cecret_key, const unsigned char *iv, FILE *ifp, FILE *ofp, int isEncrypt) {

	EVP_CIPHER_CTX *ctx_enc = EVP_CIPHER_CTX_new(); //컨텍스트 생성, 대칭키에서 복호화도 다시 암호화하는 것이니 enc라고 변수이름 지정함

	if (ctx_enc == NULL) {
		printf("암/복호화에 사용될 암호화 컨텍스트가 생성되지 않았습니다.\n");
		return -1;
	}

	//ctx_enc(컨텍스트)에 암복호화 알고리즘, 비밀키, IV, 암호화인지 복호화인지 여부를 초기화 한다.
	if (!(EVP_CipherInit_ex(ctx_enc, EVP_aes_128_cbc(), NULL, cecret_key, iv, isEncrypt))) {
		printf("암/복호화에 사용될 암호화 컨텍스트의 초기화를 실패 하였습니다.\n");
		return -1;
	}

	unsigned char *input_buf = (unsigned char*)malloc(NUM_BYTES_READ_TXT); //입력 버퍼에 최대 바이트 공간 할당
	unsigned char *output_buf = (unsigned char*)malloc(NUM_BYTES_READ_TXT + EVP_CIPHER_CTX_block_size(ctx_enc));
	//출력 버퍼에 최대 바이트 공간과 패딩 작업을 해줌, DES는 8바이트씩 암/복호화 하는데 남는 나머지 바이트를 채운다.

	if (input_buf == NULL) {
		printf("암/복호화를 위한 인풋 버퍼 할당 실패\n");
		return -1;
	}

	if (output_buf == NULL) {
		printf("암/복호화를 위한 아웃풋 버퍼 할당 실패\n");
		return -1;
	}

	int intxtlen = 0; //fread()는 size_t 자료형을 반환함(EVP 때문에 int로 수정) 읽은 바이트 수 저장 
	int outtxtlen = 0; //몇 바이트 암호화/복호화 했는지

	while (1) {
		intxtlen = (int)fread(input_buf, 1, NUM_BYTES_READ_TXT, ifp);
		//ifp(암호화 할때는 평문, 복호화 할때는 암호문).txt 파일에서 최대 바이트 수(#define)의 길이를
		// 가진 배열을 1바이트(원소의 크기)씩 읽고 input_buf에 넣음. 읽은 바이트 수가 리턴됨

		if (intxtlen <= 0)
			break;

		// 읽은 바이트 수(파일 크기)만큼 input_buf를 읽고 DES이므로 8바이트(8의 배수, 패딩된 블록은 제외)씩 
		// 암호화 시켜 output_buf에 넣는다. 암호화 시킨 바이트 수는 outtxtlen에 들어가게 됨. 성공했으면 1 반환
		if (1 != EVP_CipherUpdate(ctx_enc, output_buf, &outtxtlen, input_buf, intxtlen)) {
			printf("인풋 버퍼에서 데이터를 암/복호화 하는데 실패하였습니다.\n");
			return -1;
		}

		printf("\n 읽은 바이트 수 = %d , 암/복호화한 바이트 수 = %d", intxtlen, outtxtlen);
		printf("\n\n");


		// ofp파일에 output_buf 배열의 데이터를 1바이트씩 outtxtlen 만큼 쓰기
		fwrite(output_buf, 1, outtxtlen, ofp);

	}


	// ctx_enc는 output_buf가 어디까지 암호화 했는지 알고 있다. 8바이트씩 했으니
	// 남는 바이트(패딩)이 있을 것. 남은 바이트(패딩)을 암호화 하고
	EVP_CipherFinal(ctx_enc, output_buf, &outtxtlen);

	//처리한 패딩을 다시 쓴다.
	fwrite(output_buf, 1, outtxtlen, ofp);

	printf("\n 패딩 처리 바이트 수 = %d \n\n", outtxtlen);


	EVP_CIPHER_CTX_free(ctx_enc); //컨텍스트 할당 해제
	free(input_buf); //해제
	free(output_buf); //해제
	return 0;
}