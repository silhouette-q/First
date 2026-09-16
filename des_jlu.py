# -*- coding: utf-8 -*-
"""
des_jlu.py —— JLU 研究生选课系统登录密码加密
1:1 移植自 xsxkapp 前端 des.js（window.DES.strEncSimple）
参考值（node 原版对拍通过）：
  strEncSimple("123456") = "C1BB5938DF9F21908D35C1455E2F4800"
  strEncSimple("abc")    = "39644174795FB4D0"
算法要点：
  - 数据按 4 字符一块（每字符取 16 位 Unicode 位平面 -> 64 bit 块）
  - 密钥 "1","2","3" 各生成 16 轮子密钥，依次做加密（EEE 链）
  - 输出每块 16 个大写 hex 字符；末块不足 4 字符按 0 补齐
"""

SBOX = [
    [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],[0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
     [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],[15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],
    [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],[3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
     [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],[13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],
    [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],[13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
     [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],[1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],
    [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],[13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
     [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],[3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],
    [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],[14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
     [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],[11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],
    [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],[10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
     [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],[4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],
    [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],[13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
     [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],[6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],
    [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],[1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
     [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],[2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]],
]

# IP 置换（z 函数：0 基位选择）
IP = [39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
      37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28,
      35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26,
      33, 1, 41, 9, 49, 17, 57, 25, 32, 0, 40, 8, 48, 16, 56, 24]
# 上表是 y 函数（输出置换），z 函数（输入置换）按其逆或原表？—— z 不是标准 IP-1。
# 按 JS：z 从 64bit 输入 C 生成 L=B[0..31]/R=B[32..63]：
#   B[8i+k]   = C[8j+m]  (j 从 7 递减, m 从 1 步进 2)
#   B[8i+k+32]= C[8j+n]  (n 从 0 步进 2)
# 即 z 显式展开如下（不做猜测，直接照 JS 循环写代码）。

PC2 = [12, 15, 10, 25, 0, 4, 2, 27, 14, 5, 20, 9, 22, 18, 11, 3,
       7, 6, 19, 12, 40, 33, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47,
       43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31, 46, 55, 29, 40]
# 同上：PC2 由 w 函数 switch(H[0..47]) 显式给出，代码里直接硬编码展开。

SHIFT = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]


def _str_to_bits4(s):
    """JS a(J): 字符串(<=4字符) -> 64bit 数组；每字符 16 位，不足补 0 字符"""
    K = [0] * 64
    B = len(s)
    if B < 4:
        for H in range(B):
            F = ord(s[H])
            for G in range(16):
                I = 1
                for E in range(15, G, -1):
                    I *= 2
                K[16 * H + G] = (F // I) % 2
        for D in range(B, 4):
            F = 0  # JS: for(F=0,C=0...) F 保持 0
            for C in range(16):
                I = 1
                for E in range(15, C, -1):
                    I *= 2
                K[16 * D + C] = (F // I) % 2
    else:
        for H in range(4):
            F = ord(s[H])
            for G in range(16):
                I = 1
                for E in range(15, G, -1):
                    I *= 2
                K[16 * H + G] = (F // I) % 2
    return K


def _bits_to_hex(D):
    """JS f(D): 64bit -> 16 hex 大写字符"""
    out = []
    for i in range(16):
        v = 0
        for j in range(4):
            v = v * 2 + D[4 * i + j]
        out.append('0123456789ABCDEF'[v])
    return ''.join(out)


def _key_schedule(D):
    """JS w(D): 64bit 密钥 -> 16 组 48bit 子密钥"""
    F = [0] * 56
    G = [None] * 16
    # PC1: for E in 0..6: for j,k = j<8, k=7..0: F[8E+j] = D[8k+E]
    for E in range(7):
        k = 7
        for j in range(8):
            F[8 * E + j] = D[8 * k + E]
            k -= 1
    for E in range(16):
        for _ in range(SHIFT[E]):
            I, C = F[0], F[28]
            for k in range(27):
                F[k] = F[k + 1]
                F[28 + k] = F[29 + k]
            F[27], F[55] = I, C
        H = [13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9, 22, 18, 11, 3,
             25, 7, 15, 6, 26, 19, 12, 1, 40, 51, 30, 36, 46, 54, 29, 39,
             50, 44, 32, 47, 43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31]
        G[E] = [F[x] for x in H]
    return G


def _expand(B):
    """JS x(B): 32bit -> 48bit E 扩展"""
    C = [0] * 48
    for i in range(8):
        C[6 * i + 0] = B[31] if i == 0 else B[4 * i - 1]
        C[6 * i + 1] = B[4 * i + 0]
        C[6 * i + 2] = B[4 * i + 1]
        C[6 * i + 3] = B[4 * i + 2]
        C[6 * i + 4] = B[4 * i + 3]
        C[6 * i + 5] = B[0] if i == 7 else B[4 * i + 4]
    return C


def _xor(D, C):
    return [D[i] ^ C[i] for i in range(len(D))]


def _sbox(D):
    """JS s(D): 48bit -> 32bit 经 8 个 S 盒"""
    B = [0] * 32
    for m in range(8):
        E = 2 * D[6 * m + 0] + D[6 * m + 5]
        C = 2 * D[6 * m + 1] * 2 * 2 + 2 * D[6 * m + 2] * 2 + 2 * D[6 * m + 3] + D[6 * m + 4]
        v = SBOX[m][E][C]
        B[4 * m + 0] = v // 8 % 2
        B[4 * m + 1] = v // 4 % 2
        B[4 * m + 2] = v // 2 % 2
        B[4 * m + 3] = v % 2
    return B


def _p_perm(C):
    """JS t(C): 32bit P 置换"""
    B = [0] * 32
    tbl = [15, 6, 19, 20, 28, 11, 27, 16, 0, 14, 22, 25, 4, 17, 30, 9,
           1, 7, 23, 13, 31, 26, 2, 8, 18, 12, 29, 5, 21, 10, 3, 24]
    for i in range(32):
        B[i] = C[tbl[i]]
    return B


def _ip_out(B):
    """JS y(B): 64bit 输出置换（IP-1 位序按 JS y）"""
    C = [0] * 64
    for i, v in enumerate(IP):
        C[i] = B[v]
    return C


def _ip_in(C):
    """JS z(C): 64bit 输入置换 -> (L=R 前 32, R=后 32 视角由调用方切)"""
    B = [0] * 64
    m, n = 1, 0
    for i in range(4):
        j, k = 7, 0
        while j >= 0:
            B[8 * i + k] = C[8 * j + m]
            B[8 * i + k + 32] = C[8 * j + n]
            j -= 1
            k += 1
        m += 2
        n += 2
    return B


def _enc_block(C, M):
    """JS e(C,M): 64bit 块 C，子密钥组 M（16x48）-> 64bit"""
    L = _ip_in(C)
    D = [L[i] for i in range(32)]
    O = [L[32 + i] for i in range(32)]
    P = _key_schedule(M)
    for K in range(16):
        H = D[:]
        D = O[:]
        N = P[K][:]
        B = _p_perm(_sbox(_xor(_expand(O), N)))
        for F in range(32):
            O[F] = B[F] ^ H[F]
    E = [0] * 64
    for K in range(32):
        E[K] = O[K]
        E[32 + K] = D[K]
    return _ip_out(E)


def _key_blocks(key):
    """JS r(E): 密钥串 -> 64bit 块列表"""
    blocks = []
    n = len(key)
    full = n // 4
    for C in range(full):
        blocks.append(_str_to_bits4(key[4 * C:4 * C + 4]))
    if n % 4:
        blocks.append(_str_to_bits4(key[4 * full:n]))
    return blocks


def str_enc(data, k1, k2, k3):
    """JS d(X,Q,B,E)：主加密入口"""
    U = _key_blocks(k1) if k1 else []
    R = _key_blocks(k2) if k2 else []
    O = _key_blocks(k3) if k3 else []
    Y, G, J = len(U), len(R), len(O)
    I = ''
    H = len(data)
    if H == 0:
        return I
    if H < 4:
        N = _str_to_bits4(data)
        T = N
        for M in range(Y):
            T = _enc_block(T, U[M])
        for L in range(G):
            T = _enc_block(T, R[L])
        for K in range(J):
            T = _enc_block(T, O[K])
        I = _bits_to_hex(T)
    else:
        P = H // 4
        for S in range(P):
            W = _str_to_bits4(data[4 * S:4 * S + 4])
            T = W
            for M in range(Y):
                T = _enc_block(T, U[M])
            for L in range(G):
                T = _enc_block(T, R[L])
            for K in range(J):
                T = _enc_block(T, O[K])
            I += _bits_to_hex(T)
        if H % 4:
            W = _str_to_bits4(data[4 * P:H])
            T = W
            for M in range(Y):
                T = _enc_block(T, U[M])
            for L in range(G):
                T = _enc_block(T, R[L])
            for K in range(J):
                T = _enc_block(T, O[K])
            I += _bits_to_hex(T)
    return I


def str_enc_simple(text):
    """前端登录用：DES.strEncSimple(密码)"""
    return str_enc(text, '1', '2', '3')


if __name__ == '__main__':
    cases = {
        '123456': 'C1BB5938DF9F21908D35C1455E2F4800',
        '2023010001': '494845A373A4576BB9480B2FD3B5F8561BDC705FD7525DC8',
        'abc': '39644174795FB4D0',
        '11010120000101123X': 'AD1ED9AD7855D344079F751E15894D8C3C137590495BDF445AFE23CD3829A9447D4CB79BCB523FD8',
        '2023010001x1': '494845A373A4576BB9480B2FD3B5F856F6E3EB7EA0A9F634',
    }
    ok = True
    for plain, want in cases.items():
        got = str_enc_simple(plain)
        status = 'OK ' if got == want else 'FAIL'
        if got != want:
            ok = False
        print(f'[{status}] {plain!r}: got={got} want={want}')
    print('ALL_PASS' if ok else 'SOME_FAIL')
