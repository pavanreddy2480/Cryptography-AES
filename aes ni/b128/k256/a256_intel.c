#include <stdint.h> //for int8_t
#include <stdio.h>
#include <string.h> //for memcmp
#include <wmmintrin.h>

static unsigned char key_schedule[340];

void KEY_192_ASSIST(__m128i *temp1, __m128i *temp2, __m128i *temp3) {
  __m128i temp4;
  *temp2 = _mm_shuffle_epi32(*temp2, 0x55);
  temp4 = _mm_slli_si128(*temp1, 0x4);
  *temp1 = _mm_xor_si128(*temp1, temp4);
  temp4 = _mm_slli_si128(temp4, 0x4);
  *temp1 = _mm_xor_si128(*temp1, temp4);
  temp4 = _mm_slli_si128(temp4, 0x4);
  *temp1 = _mm_xor_si128(*temp1, temp4);
  *temp1 = _mm_xor_si128(*temp1, *temp2);
  *temp2 = _mm_shuffle_epi32(*temp1, 0xff);
  temp4 = _mm_slli_si128(*temp3, 0x4);
  *temp3 = _mm_xor_si128(*temp3, temp4);
  *temp3 = _mm_xor_si128(*temp3, *temp2);
}

void AES_192_Key_Expansion(const unsigned char *userkey, unsigned char *key) {
  __m128i temp1, temp2, temp3, temp4;
  __m128i *Key_Schedule = (__m128i *)key;
  temp1 = _mm_loadu_si128((__m128i *)userkey);
  temp3 = _mm_loadu_si128((__m128i *)(userkey + 16));
  Key_Schedule[0] = temp1;
  Key_Schedule[1] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x1);
  KEY_192_ASSIST(&temp1, &temp2, &temp3);
  Key_Schedule[1] =
      (__m128i)_mm_shuffle_pd((__m128d)Key_Schedule[1], (__m128d)temp1, 0);
  Key_Schedule[2] = (__m128i)_mm_shuffle_pd((__m128d)temp1, (__m128d)temp3, 1);
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x2);
  KEY_192_ASSIST(&temp1, &temp2, &temp3);
  Key_Schedule[3] = temp1;
  Key_Schedule[4] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x4);
  KEY_192_ASSIST(&temp1, &temp2, &temp3);
  Key_Schedule[4] =
      (__m128i)_mm_shuffle_pd((__m128d)Key_Schedule[4], (__m128d)temp1, 0);
  Key_Schedule[5] = (__m128i)_mm_shuffle_pd((__m128d)temp1, (__m128d)temp3, 1);
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x8);
  KEY_192_ASSIST(&temp1, &temp2, &temp3);
  Key_Schedule[6] = temp1;
  Key_Schedule[7] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x10);
  KEY_192_ASSIST(&temp1, &temp2, &temp3);
  Key_Schedule[7] =
      (__m128i)_mm_shuffle_pd((__m128d)Key_Schedule[7], (__m128d)temp1, 0);
  Key_Schedule[8] = (__m128i)_mm_shuffle_pd((__m128d)temp1, (__m128d)temp3, 1);
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x20);
  KEY_192_ASSIST(&temp1, &temp2, &temp3);
  Key_Schedule[9] = temp1;
  Key_Schedule[10] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x40);
  KEY_192_ASSIST(&temp1, &temp2, &temp3);
  Key_Schedule[10] =
      (__m128i)_mm_shuffle_pd((__m128d)Key_Schedule[10], (__m128d)temp1, 0);
  Key_Schedule[11] = (__m128i)_mm_shuffle_pd((__m128d)temp1, (__m128d)temp3, 1);
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x80);
  KEY_192_ASSIST(&temp1, &temp2, &temp3);
  Key_Schedule[12] = temp1;
}

void AES_ECB_encrypt(const unsigned char *in, // pointer to the PLAINTEXT
                     unsigned char *out,   // pointer to the CIPHERTEXT buffer
                     unsigned long length, // text length in bytes
                     unsigned char *key, // pointer to the expanded key schedule
                     int number_of_rounds) // number of AES rounds 10,12 or 14
{
  __m128i tmp;
  int i, j;
  if (length % 16)
    length = length / 16 + 1;
  else
    length = length / 16;
  for (i = 0; i < length; i++) {
    tmp = _mm_loadu_si128(&((__m128i *)in)[i]);
    tmp = _mm_xor_si128(tmp, ((__m128i *)key)[0]);
    for (j = 1; j < number_of_rounds; j++) {
      tmp = _mm_aesenc_si128(tmp, ((__m128i *)key)[j]);
    }
    tmp = _mm_aesenclast_si128(tmp, ((__m128i *)key)[j]);
    _mm_storeu_si128(&((__m128i *)out)[i], tmp);
  }
}

void AES_ECB_decrypt(const unsigned char *in, // pointer to the CIPHERTEXT
                     unsigned char *out, // pointer to the DECRYPTED TEXT buffer
                     unsigned long length, // text length in bytes
                     unsigned char *key, // pointer to the expanded key schedule
                     int number_of_rounds) // number of AES rounds 10,12 or 14
{
  __m128i tmp;
  int i, j;
  if (length % 16)
    length = length / 16 + 1;
  else
    length = length / 16;
  for (i = 0; i < length; i++) {
    tmp = _mm_loadu_si128(&((__m128i *)in)[i]);
    tmp = _mm_xor_si128(tmp, ((__m128i *)key)[0]);
    for (j = 1; j < number_of_rounds; j++) {
      tmp = _mm_aesdec_si128(tmp, ((__m128i *)key)[j]);
    }
    tmp = _mm_aesdeclast_si128(tmp, ((__m128i *)key)[j]);
    _mm_storeu_si128(&((__m128i *)out)[i], tmp);
  }
}

int aes128_self_test(void) {
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
  AES_192_Key_Expansion(enc_key, key_schedule);
  for(int i=0;i<sizeof(plain);i++){
    printf("%c",plain[i]);
  }
  printf("\n");

  AES_ECB_encrypt(plain, computed_cipher, 16, key_schedule, 12);
  // aes128_dec(computed_cipher,computed_plain);
  AES_ECB_decrypt(computed_cipher, computed_plain, 16, key_schedule, 12);
  
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
  // if(memcmp(cipher,computed_cipher,sizeof(cipher))) out=1;
  if (memcmp(plain, computed_plain, sizeof(plain)))
    out |= 2;
  return out;
}
int main() {
  int a = aes128_self_test();
  printf("%d", a);
  return 0;
}
// int main(){
//   unsigned char key[288];
//   unsigned char userkey[24];
//   AES_192_Key_Expansion(userkey, key);

// }
