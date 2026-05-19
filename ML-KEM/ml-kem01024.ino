#include <Arduino.h>
#include <SHAKE.h>
#include <esp_system.h>
#include "esp_heap_caps.h"
#include <cstring>

#define N 256
#define Q 3329
#define K 4
#define ETA1 3
#define ROUNDS 1000

SHAKE128 shake;

// ================= RANDOM =================
void randombytes(uint8_t *buf, size_t len){
  for(size_t i=0;i<len;i++)
    buf[i] = esp_random() & 0xFF;
}

// ================= ZETAS =================
int16_t zetas[N] = {
 -1044,-758,-359,-1517,1493,1422,287,202,-171,622,1577,182,962,-1202,-1474,1468,
 573,-1325,264,383,-829,1458,-1602,-130,-681,1017,732,608,-1542,411,-205,-1571,
 1223,652,-552,1015,-1293,1491,-282,-1544,516,-8,-320,-666,-1618,-1162,126,1469,
 -853,-90,-271,830,107,-1421,-247,-951,-398,961,-1508,-725,448,-1065,677,-1275,
 -1103,430,555,843,-1251,871,1550,105,422,587,177,-235,-291,-460,1574,1653,
 -246,778,1159,-147,-777,1483,-602,1119,-1590,644,-872,349,418,329,-156,-75,
 817,1097,603,610,1322,-1285,-1465,384,-1215,-136,1218,-1335,-874,220,-1187,-1659,
 -1185,-1530,-1278,794,-1510,-854,-870,478,-108,-308,996,991,958,-1460,1522,1628
};

// ================= MOD =================
inline int16_t modq(int32_t a){
  a %= Q;
  if(a < 0) a += Q;
  return (int16_t)a;
}

// ================= POLY =================
void poly_add(int16_t *r,const int16_t *a,const int16_t *b){
  for(int i=0;i<N;i++) r[i]=modq(a[i]+b[i]);
}

void poly_sub(int16_t *r,const int16_t *a,const int16_t *b){
  for(int i=0;i<N;i++) r[i]=modq(a[i]-b[i]);
}

void poly_mul(int16_t *r,int16_t *a,int16_t *b){
  int32_t tmp[N]={0};

  for(int i=0;i<N;i++)
    for(int j=0;j<N;j++)
      tmp[(i+j)&(N-1)] += a[i]*b[j];

  for(int i=0;i<N;i++)
    r[i]=modq(tmp[i]);
}

// ================= CBD =================
void cbd(int16_t *r,int eta){
  uint8_t buf[N*eta];
  randombytes(buf,sizeof(buf));

  for(int i=0;i<N;i++){
    int a=0,b=0;
    for(int j=0;j<eta;j++){
      a += buf[i*eta+j] & 1;
      b += (buf[i*eta+j] >> 1) & 1;
    }
    r[i]=a-b;
  }
}

// ================= SHAKE (FIXED) =================
void shake128_hash(uint8_t *out,const uint8_t *in,size_t inlen,size_t outlen){
  shake.reset();
  shake.update(in,inlen);
  shake.extend(out,outlen);   // ✅ corect pentru libraria ta
}

// ================= CONSTANT TIME =================
uint8_t ct_memcmp(const uint8_t *a,const uint8_t *b,size_t n){
  uint8_t r=0;
  for(size_t i=0;i<n;i++) r |= a[i]^b[i];
  return r;
}

uint8_t ct_select(uint8_t a,uint8_t b,uint8_t cond){
  uint8_t mask = -(cond != 0);
  return (a & ~mask) | (b & mask);
}

// ================= KEYGEN =================
void keygen(int16_t A[K][K][N], int16_t s[K][N], int16_t e[K][N], int16_t t[K][N]){

  uint8_t seed[32];
  randombytes(seed,32);

  for(int i=0;i<K;i++)
    for(int j=0;j<K;j++)
      for(int k=0;k<N;k++)
        A[i][j][k]=esp_random()%Q;

  for(int i=0;i<K;i++){
    cbd(s[i],ETA1);
    cbd(e[i],ETA1);
  }

  for(int i=0;i<K;i++){
    int16_t tmp[N]={0};

    for(int j=0;j<K;j++){
      int16_t prod[N];
      poly_mul(prod,A[i][j],s[j]);
      poly_add(tmp,tmp,prod);
    }

    poly_add(t[i],tmp,e[i]);
  }

  memset(seed,0,sizeof(seed));
}

// ================= FAKE KEM =================
void encaps(uint8_t ss[32]){ randombytes(ss,32); }
void decaps(uint8_t ss[32]){ randombytes(ss,32); }

// ================= MEMORY =================
void printMemory(){
  uint32_t total = heap_caps_get_total_size(MALLOC_CAP_8BIT);
  uint32_t free  = esp_get_free_heap_size();

  Serial.printf("Heap used: %.2f KB\n", (total-free)/1024.0);
  Serial.println("---");
}

// ================= SETUP =================
void setup(){
  Serial.begin(115200);
  delay(1000);

  Serial.println("ML-KEM ESP32 FIXED BUILD");

  static int16_t A[K][K][N];
  static int16_t s[K][N], e[K][N], t[K][N];

  uint8_t ss1[32], ss2[32];

  for(int r=0;r<ROUNDS;r++){
    Serial.printf("Round %d\n", r+1);

    unsigned long t0=micros();
    keygen(A,s,e,t);
    Serial.printf("KeyGen: %lu us\n", micros()-t0);

    encaps(ss1);
    decaps(ss2);

    printMemory();
    Serial.println("---");
  }
}

void loop(){}
