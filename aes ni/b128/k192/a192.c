#include <stdint.h>
#include <string.h>
#include <wmmintrin.h>
#include <stdio.h>

#define DO_ENC_BLOCK(m,k) \
	do{\
        m = _mm_xor_si128       (m, k[ 0]); \
        m = _mm_aesenc_si128    (m, k[ 1]); \
        m = _mm_aesenc_si128    (m, k[ 2]); \
        m = _mm_aesenc_si128    (m, k[ 3]); \
        m = _mm_aesenc_si128    (m, k[ 4]); \
        m = _mm_aesenc_si128    (m, k[ 5]); \
        m = _mm_aesenc_si128    (m, k[ 6]); \
        m = _mm_aesenc_si128    (m, k[ 7]); \
        m = _mm_aesenc_si128    (m, k[ 8]); \
        m = _mm_aesenc_si128    (m, k[ 9]); \
        m = _mm_aesenc_si128    (m, k[10]); \
        m = _mm_aesenc_si128    (m, k[11]); \
        m = _mm_aesenclast_si128(m, k[12]);\
    }while(0)

#define DO_DEC_BLOCK(m,k) \
	do{\
        m = _mm_xor_si128       (m, k[12+0]); \
        m = _mm_aesdec_si128    (m, k[12+1]); \
        m = _mm_aesdec_si128    (m, k[12+2]); \
        m = _mm_aesdec_si128    (m, k[12+3]); \
        m = _mm_aesdec_si128    (m, k[12+4]); \
        m = _mm_aesdec_si128    (m, k[12+5]); \
        m = _mm_aesdec_si128    (m, k[12+6]); \
        m = _mm_aesdec_si128    (m, k[12+7]); \
        m = _mm_aesdec_si128    (m, k[12+8]); \
        m = _mm_aesdec_si128    (m, k[12+9]); \
        m = _mm_aesdec_si128    (m, k[12+10]); \
        m = _mm_aesdec_si128    (m, k[12+11]); \
        m = _mm_aesdeclast_si128(m, k[0]);\
    }while(0)

#define AES_192_key_exp(k, rcon) aes_192_key_expansion(k, _mm_aeskeygenassist_si128(k, rcon))

static __m128i key_schedule[26];  // the expanded key for AES-192

static __m128i aes_192_key_expansion(__m128i key, __m128i keygened) {
    keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3, 3, 3, 3));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, keygened);
}

void aes192_load_key(unsigned char *enc_key){
    key_schedule[0] = _mm_loadu_si128((const __m128i*) enc_key);
    key_schedule[1] = AES_192_key_exp(key_schedule[0], 0x01);
    key_schedule[2] = AES_192_key_exp(key_schedule[1], 0x02);
    key_schedule[3] = AES_192_key_exp(key_schedule[2], 0x04);
    key_schedule[4] = AES_192_key_exp(key_schedule[3], 0x08);
    key_schedule[5] = AES_192_key_exp(key_schedule[4], 0x10);
    key_schedule[6] = AES_192_key_exp(key_schedule[5], 0x20);
    key_schedule[7] = AES_192_key_exp(key_schedule[6], 0x40);
    key_schedule[8] = AES_192_key_exp(key_schedule[7], 0x80);
    key_schedule[9] = AES_192_key_exp(key_schedule[8], 0x1B);
    key_schedule[10] = AES_192_key_exp(key_schedule[9], 0x36);
    key_schedule[11] = AES_192_key_exp(key_schedule[10], 0x6C);
    key_schedule[12] = AES_192_key_exp(key_schedule[11], 0xD8);

    key_schedule[13] = _mm_aesimc_si128(key_schedule[11]);
    key_schedule[14] = _mm_aesimc_si128(key_schedule[10]);
    key_schedule[15] = _mm_aesimc_si128(key_schedule[9]);
    key_schedule[16] = _mm_aesimc_si128(key_schedule[8]);
    key_schedule[17] = _mm_aesimc_si128(key_schedule[7]);
    key_schedule[18] = _mm_aesimc_si128(key_schedule[6]);
    key_schedule[19] = _mm_aesimc_si128(key_schedule[5]);
    key_schedule[20] = _mm_aesimc_si128(key_schedule[4]);
    key_schedule[21] = _mm_aesimc_si128(key_schedule[3]);
    key_schedule[22] = _mm_aesimc_si128(key_schedule[2]);
    key_schedule[23] = _mm_aesimc_si128(key_schedule[1]);
    key_schedule[24] = _mm_aesimc_si128(key_schedule[0]);
    key_schedule[25] = _mm_loadu_si128((const __m128i*) (enc_key+16));
}


void aes192_enc(unsigned char *plainText, unsigned char *cipherText) {
    __m128i m = _mm_loadu_si128((__m128i *)plainText);
    DO_ENC_BLOCK(m, key_schedule);
    _mm_storeu_si128((__m128i *)cipherText, m);
}

void aes192_dec(unsigned char *cipherText, unsigned char *plainText) {
    __m128i m = _mm_loadu_si128((__m128i *)cipherText);
    DO_DEC_BLOCK(m, key_schedule);
    _mm_storeu_si128((__m128i *)plainText, m);
}

int aes192_self_test(void) {
    unsigned char plain[16];
    unsigned char enc_key[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    unsigned char computed_cipher[16];
    unsigned char computed_plain[16];
    int out = 0;

    printf("Enter plaintext (16 characters): ");
    scanf("%s", plain);

    int input_length = strlen((const char *)plain);
    if (input_length < 16) {
        memset(plain + input_length, 0, 16 - input_length);
    }

    aes192_load_key(enc_key);
    aes192_enc(plain, computed_cipher);
    aes192_dec(computed_cipher, computed_plain);

    printf("Computed Cipher: ");
    for (int i = 0; i < sizeof(computed_cipher); i++) {
        printf("%02x ", computed_cipher[i]);
    }
    printf("\n");

    printf("Computed Plain Text: ");
    for (int i = 0; i < sizeof(computed_plain); i++) {
        printf("%c", computed_plain[i]);
    }
    printf("\n");

    if (memcmp(plain, computed_plain, sizeof(plain))) {
        out |= 2;
    }

    return out;
}

int main() {
    int result = aes192_self_test();
    printf("Test Result: %d\n", result);
    return 0;
}
