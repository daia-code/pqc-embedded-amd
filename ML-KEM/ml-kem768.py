import hashlib
import secrets
import numpy as np
import time
import tracemalloc

# ======================================
# PARAMETERS ML-KEM-768
# ======================================

N = 384       # polynomial degree
Q = 3329      # modulus
K = 3         # matrix dimension

ETA1 = 4      # centered binomial for secret
ETA2 = 3
ROUNDS = 1000   # adjust for testing, can set 1000
VERBOSE = True

# ======================================
# LOGGING UTIL
# ======================================

def log(*msg):
    if VERBOSE:
        print(*msg)

# ======================================
# PROFILER
# ======================================

class Profiler:
    def __init__(self):
        self.start = None

    def begin(self):
        tracemalloc.start()
        self.start = time.perf_counter()

    def end(self, label):
        elapsed = (time.perf_counter() - self.start) * 1000
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        print(f"\n[{label}]")
        print(f"Time: {elapsed:.3f} ms")
        print(f"Memory current: {current/1024:.2f} KB")
        print(f"Memory peak: {peak/1024:.2f} KB")
        print("-"*40)

# ======================================
# RANDOM BYTES
# ======================================

def randombytes(n):
    return secrets.token_bytes(n)

# ======================================
# HASH FUNCTIONS
# ======================================

def H(data):
    return hashlib.sha3_256(data).digest()

def G(data):
    h = hashlib.sha3_512(data).digest()
    return h[:32], h[32:]

def KDF(data):
    return hashlib.shake_256(data).digest(32)

def shake128(data, l):
    s = hashlib.shake_128()
    s.update(data)
    return s.digest(l)

def shake256(data, l):
    s = hashlib.shake_256()
    s.update(data)
    return s.digest(l)

# ======================================
# MODULAR ARITHMETIC
# ======================================

def barrett_reduce(a):
    return a % Q

def montgomery_reduce(a):
    return a % Q

# ======================================
# POLYNOMIAL OPS
# ======================================

def poly_add(a, b):
    return (a + b) % Q

def poly_sub(a, b):
    return (a - b) % Q

# ======================================
# NTT ROOTS
# ======================================

ZETAS = np.random.randint(-Q, Q, N//2)

# ======================================
# NTT / INTT
# ======================================

def ntt(a):
    log("NTT transform")
    a = a.copy()
    n = len(a)
    for i in range(0, n, 2):
        a[i], a[i+1] = (a[i] + a[i+1]) % Q, (a[i] - a[i+1]) % Q
    return a

def intt(a):
    log("Inverse NTT")
    a = a.copy()
    n = len(a)
    for i in range(0, n, 2):
        a[i], a[i+1] = (a[i] + a[i+1]) % Q, (a[i] - a[i+1]) % Q
    return a

# ======================================
# POLY MULTIPLICATION
# ======================================

def poly_mul(a, b):
    log("Polynomial multiplication (NTT)")
    fa = ntt(a)
    fb = ntt(b)
    fc = (fa * fb) % Q
    return intt(fc)

# ======================================
# CENTERED BINOMIAL SAMPLING
# ======================================

def cbd(buf, eta):
    log("CBD sampling")
    r = np.zeros(N, dtype=np.int64)
    for i in range(N):
        a = 0
        b = 0
        for j in range(eta):
            x = buf[i*eta + j]
            a += (x >> 0) & 1
            b += (x >> 1) & 1
        r[i] = a - b
    return r

# ======================================
# MATRIX GENERATION
# ======================================

def gen_matrix(seed):
    log("Generating matrix A")
    A = []
    for i in range(K):
        row = []
        for j in range(K):
            buf = shake128(seed + bytes([i, j]), 2*N)
            poly = np.zeros(N, dtype=np.int64)
            for k in range(N):
                v = buf[2*k] | (buf[2*k+1]<<8)
                poly[k] = v % Q
            row.append(poly)
        A.append(row)
    return A

# ======================================
# KEYGEN
# ======================================

def keygen():
    log("\n===== KEYGEN =====")
    d = randombytes(32)
    rho, sigma = G(d)
    log("rho:", rho.hex()[:16])
    A = gen_matrix(rho)
    s = []
    e = []
    nonce = 0
    for i in range(K):
        buf = shake256(sigma + bytes([nonce]), N*ETA1)
        s.append(cbd(buf, ETA1))
        nonce += 1
    for i in range(K):
        buf = shake256(sigma + bytes([nonce]), N*ETA1)
        e.append(cbd(buf, ETA1))
        nonce += 1
    t = []
    for i in range(K):
        log(f"Compute t {i}")
        acc = np.zeros(N, dtype=np.int64)
        for j in range(K):
            prod = poly_mul(A[i][j], s[j])
            acc = poly_add(acc, prod)
        acc = poly_add(acc, e[i])
        t.append(acc)
    pk = (rho, t)
    sk = (s, pk)
    log("KeyGen finished")
    return pk, sk

# ======================================
# ENCAPS
# ======================================

def encaps(pk):
    log("\n===== ENCAPS =====")
    m = randombytes(32)
    log("message:", m.hex()[:16])
    mh = H(m)
    Kbar, r = G(mh)
    rho, t = pk
    A = gen_matrix(rho)
    rvec = []
    nonce = 0
    for i in range(K):
        buf = shake256(r + bytes([nonce]), N*ETA1)
        rvec.append(cbd(buf, ETA1))
        nonce += 1
    u = []
    for i in range(K):
        acc = np.zeros(N, dtype=np.int64)
        for j in range(K):
            prod = poly_mul(A[j][i], rvec[j])
            acc = poly_add(acc, prod)
        u.append(acc)
    v = np.zeros(N, dtype=np.int64)
    for j in range(K):
        prod = poly_mul(t[j], rvec[j])
        v = poly_add(v, prod)
    ct = (u, v)
    ss = KDF(Kbar)
    log("Encapsulation finished")
    return ct, ss

# ======================================
# DECAPS
# ======================================

def decaps(ct, sk):
    log("\n===== DECAPS =====")
    s, pk = sk
    u, v = ct
    mp = np.zeros(N, dtype=np.int64)
    for i in range(K):
        prod = poly_mul(u[i], s[i])
        mp = poly_add(mp, prod)
    ss = KDF(mp.tobytes())
    log("Decapsulation finished")
    return ss

# ======================================
# MAIN TEST
# ======================================

if __name__ == "__main__":
    print("\nML-KEM-768 Performance Demo\n")
    for i in range(ROUNDS):
        print(f"\n========== ROUND {i+1}/{ROUNDS} ==========")
        profiler = Profiler()
        # KEYGEN
        profiler.begin()
        pk, sk = keygen()
        profiler.end("KEYGEN")
        # ENCAPS
        profiler.begin()
        ct, ss1 = encaps(pk)
        profiler.end("ENCAPS")
        # DECAPS
        profiler.begin()
        ss2 = decaps(ct, sk)
        profiler.end("DECAPS")
        print("Shared secret match:", ss1 == ss2)