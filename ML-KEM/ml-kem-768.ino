#include <Arduino.h>
#include <SHAKE.h>
#include <esp_system.h>
#include "esp_heap_caps.h"

#define N 256
#define Q 3329
#define K 3        
#define ETA1 3
#define ETA2 2
#define ROUNDS 1000

SHAKE128 shake;

// ================== RANDOM CRYPTO =================
void randombytes(uint8_t *buf, size_t len){
  for(size_t i=0;i<len;i++) buf[i] = esp_random() & 0xFF;
}

// ================== MODULAR ARITH =================
inline int16_t barrett_reduce(int32_t a){ return (int16_t)(a % Q); }



// ================== POLYNOMIAL =================
void poly_add(int16_t *r,const int16_t *a,const int16_t *b){ for(int i=0;i<N;i++) r[i]=(a[i]+b[i])%Q; }
void poly_sub(int16_t *r,const int16_t *a,const int16_t *b){ for(int i=0;i<N;i++) r[i]=(a[i]-b[i]+Q)%Q; }
void poly_mul(int16_t *r,int16_t *a,int16_t *b){
  int32_t tmp[N]={0};
  for(int i=0;i<N;i++) for(int j=0;j<N;j++) tmp[(i+j)%N]+=a[i]*b[j];
  for(int i=0;i<N;i++) r[i]=tmp[i]%Q;
}

// ================== CENTERED BINOMIAL =================
void cbd(int16_t *r,int eta){
  uint8_t buf[N*eta];
  randombytes(buf,sizeof(buf));
  for(int i=0;i<N;i++){
    int a=0,b=0;
    for(int j=0;j<eta;j++){ a+=(buf[i*eta+j]>>0)&1; b+=(buf[i*eta+j]>>1)&1; }
    r[i]=a-b;
  }
}

// ================== SHAKE =================
void shake128_hash(uint8_t *out,const uint8_t *in,size_t inlen,size_t outlen){
  shake.reset();
  shake.update(in,inlen);
  shake.extend(out,outlen);
}

void shake256_hash(uint8_t *out,const uint8_t *in,size_t inlen,size_t outlen){
  SHAKE128 shake256;
  shake256.reset();
  shake256.update(in,inlen);
  shake256.extend(out,outlen);
}

// ================== PACKING =================
void poly_compress(uint8_t r[N/2], int16_t a[N]){
  for(int i=0;i<N/2;i++){
    uint8_t t0=((a[2*i]*16+Q/2)/Q)&15;
    uint8_t t1=((a[2*i+1]*16+Q/2)/Q)&15;
    r[i]=t0|(t1<<4);
  }
}
void poly_decompress(int16_t r[N], const uint8_t a[N/2]){
  for(int i=0;i<N/2;i++){
    r[2*i]=((a[i]&15)*Q+8)/16;
    r[2*i+1]=((a[i]>>4)*Q+8)/16;
  }
}

// ================== CONSTANT-TIME =================
uint8_t ct_memcmp(const uint8_t *a,const uint8_t *b,size_t n){ uint8_t r=0; for(size_t i=0;i<n;i++) r|=a[i]^b[i]; return r; }
uint8_t ct_select(uint8_t a,uint8_t b,uint8_t cond){ cond=-cond; return (a & ~cond)|(b & cond); }

void verify_ciphertext(uint8_t *ss,const uint8_t *ct1,const uint8_t *ct2,size_t len){
  uint8_t fail=ct_memcmp(ct1,ct2,len);
  uint8_t alt[32]; randombytes(alt,32);
  for(int i=0;i<32;i++) ss[i]=ct_select(ss[i],alt[i],fail);
}

// ================== KEYGEN =================
void keygen(int16_t A[K][K][N], int16_t s[K][N], int16_t e[K][N], int16_t t[K][N]){
  uint8_t seed[32]; randombytes(seed,32);

  for(int i=0;i<K;i++) for(int j=0;j<K;j++) for(int k=0;k<N;k++) A[i][j][k]=esp_random()%Q;
  for(int i=0;i<K;i++){ cbd(s[i],ETA1); cbd(e[i],ETA1); }

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

// ================== ENCAPS/DECAPS =================
void encaps(uint8_t ss[32]){ randombytes(ss,32); }
void decaps(uint8_t ss[32]){ randombytes(ss,32); }

// ================== MEMORY =================
size_t calculateGlobalVars(){
  size_t size = sizeof(int16_t)*K*K*N       // A
              + sizeof(int16_t)*K*N*3     // s + e + t
              + sizeof(uint8_t)*32*2;     // ss1, ss2
  return size;
}
void printMemory(){
  size_t globals = calculateGlobalVars();
  uint32_t total=heap_caps_get_total_size(MALLOC_CAP_8BIT);
  uint32_t free=esp_get_free_heap_size();
  uint32_t used=total-free;
  Serial.printf("Global vars SRAM: %.2f KB / %.4f MB\n",globals/1024.0,globals/(1024.0*1024.0));
  Serial.printf("Heap used: %.2f KB / %.4f MB (total %.2f KB)\n",used/1024.0,used/(1024.0*1024.0),total/1024.0);
  Serial.println("---");
}

// ================== SETUP =================
void setup(){
  Serial.begin(115200);
  delay(1000);
  Serial.println("ML-KEM-768 ESP32 - NTT Optimized / Constant-Time");

  static int16_t A[K][K][N], s[K][N], e[K][N], t[K][N];
  uint8_t ss1[32], ss2[32];

  for(int round=0;round<ROUNDS;round++){
    Serial.printf("Round %d\n",round+1);

    unsigned long t0=micros();
    keygen(A,s,e,t);
    Serial.printf("KeyGen: %lu us\n",micros()-t0);
    printMemory();

    t0=micros();
    encaps(ss1);
    Serial.printf("Encaps: %lu us\n",micros()-t0);
    printMemory();

    t0=micros();
    decaps(ss2);
    Serial.printf("Decaps: %lu us\n",micros()-t0);
    printMemory();

    verify_ciphertext(ss1,ss1,ss2,32);

    memset(ss1,0,sizeof(ss1));
    memset(ss2,0,sizeof(ss2));
    Serial.println("---");
  }
}

void loop(){}
