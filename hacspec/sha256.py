from hacspec.speclib import *

i_range_t = range_t(0, 4)
op_range_t = range_t(0, 1)

# Initializing types and constants
blockSize : int = 64
block_t = bytes_t(blockSize)
lenSize : int = 8
len_t = uint64_t
to_len : FunctionType = uint64
len_to_bytes : FunctionType = bytes.from_uint64_be
word_t = uint32_t
to_word : FunctionType = uint32
bytes_to_words : FunctionType = bytes.to_uint32s_be
words_to_bytes : FunctionType = bytes.from_uint32s_be
kSize : int = 64
k_t = array_t(word_t,kSize)
opTableType_t = array_t(int,12)
opTable : opTableType_t = opTableType_t([
    2, 13, 22,
    6, 11, 25,
    7, 18, 3,
    17, 19, 10])
kTable : k_t = k_t([
    uint32(0x428a2f98), uint32(0x71374491), uint32(0xb5c0fbcf), uint32(0xe9b5dba5),
    uint32(0x3956c25b), uint32(0x59f111f1), uint32(0x923f82a4), uint32(0xab1c5ed5),
    uint32(0xd807aa98), uint32(0x12835b01), uint32(0x243185be), uint32(0x550c7dc3),
    uint32(0x72be5d74), uint32(0x80deb1fe), uint32(0x9bdc06a7), uint32(0xc19bf174),
    uint32(0xe49b69c1), uint32(0xefbe4786), uint32(0x0fc19dc6), uint32(0x240ca1cc),
    uint32(0x2de92c6f), uint32(0x4a7484aa), uint32(0x5cb0a9dc), uint32(0x76f988da),
    uint32(0x983e5152), uint32(0xa831c66d), uint32(0xb00327c8), uint32(0xbf597fc7),
    uint32(0xc6e00bf3), uint32(0xd5a79147), uint32(0x06ca6351), uint32(0x14292967),
    uint32(0x27b70a85), uint32(0x2e1b2138), uint32(0x4d2c6dfc), uint32(0x53380d13),
    uint32(0x650a7354), uint32(0x766a0abb), uint32(0x81c2c92e), uint32(0x92722c85),
    uint32(0xa2bfe8a1), uint32(0xa81a664b), uint32(0xc24b8b70), uint32(0xc76c51a3),
    uint32(0xd192e819), uint32(0xd6990624), uint32(0xf40e3585), uint32(0x106aa070),
    uint32(0x19a4c116), uint32(0x1e376c08), uint32(0x2748774c), uint32(0x34b0bcb5),
    uint32(0x391c0cb3), uint32(0x4ed8aa4a), uint32(0x5b9cca4f), uint32(0x682e6ff3),
    uint32(0x748f82ee), uint32(0x78a5636f), uint32(0x84c87814), uint32(0x8cc70208),
    uint32(0x90befffa), uint32(0xa4506ceb), uint32(0xbef9a3f7), uint32(0xc67178f2)])


hashSize : int = 32
hash_t = array_t(word_t,8)
digest_t = bytes_t(hashSize)
h0_t = bytes_t(8)
h0: h0_t = array.create(8,to_word(0))
h0 = hash_t([
    uint32(0x6a09e667), uint32(0xbb67ae85), uint32(0x3c6ef372), uint32(0xa54ff53a),
    uint32(0x510e527f), uint32(0x9b05688c), uint32(0x1f83d9ab), uint32(0x5be0cd19)])

# Initialization complete: SHA-2 spec begins
@typechecked
def ch(x:word_t,y:word_t,z:word_t) -> word_t:
    return (x & y) ^ ((~ x) & z)

@typechecked
def maj(x:word_t,y:word_t,z:word_t) -> word_t:
    return (x & y) ^ ((x & z) ^ (y & z))

@typechecked
def sigma(x:word_t,i:i_range_t,op:op_range_t) -> word_t:
    tmp : uintn_t
    if op == 0:
        tmp = x >> opTable[3*i+2]
    else:
        tmp = uintn.rotate_right(x,opTable[3*i+2])
    return (uintn.rotate_right(x,opTable[3*i]) ^
            uintn.rotate_right(x,opTable[3*i+1]) ^
            tmp)

@typechecked
def schedule(block:block_t) -> k_t:
    b : bytes_t = bytes_to_words(block)
    s : vlbytes_t = array.create(kSize,to_word(0))
    for i in range(kSize):
        if i < 16:
            s[i] = b[i]
        else:
            t16 : word_t = s[i-16]
            t15 : word_t = s[i-15]
            t7  : word_t = s[i-7]
            t2  : word_t = s[i-2]
            s1  : word_t = sigma(t2,3,0)
            s0  : word_t = sigma(t15,2,0)
            s[i] = s1 + t7 + s0 + t16
    return s

@typechecked
def shuffle(ws:k_t,hashi:hash_t) -> hash_t:
    h = array.copy(hashi)
    for i in range(kSize):
        a0 : word_t = h[0]
        b0 : word_t = h[1]
        c0 : word_t = h[2]
        d0 : word_t = h[3]
        e0 : word_t = h[4]
        f0 : word_t = h[5]
        g0 : word_t = h[6]
        h0 : word_t = h[7]

        t1 : word_t = h0 + sigma(e0,1,1) + ch(e0,f0,g0) + kTable[i] + ws[i]
        t2 : word_t = sigma(a0,0,1) + maj(a0,b0,c0)

        h[0] = t1 + t2
        h[1] = a0
        h[2] = b0
        h[3] = c0
        h[4] = d0 + t1
        h[5] = e0
        h[6] = f0
        h[7] = g0
    return h

@typechecked
def compress(block:block_t,hIn:hash_t) -> hash_t:
    s : k_t = schedule(block)
    h : hash_t = shuffle(s,hIn)
    for i in range(8):
        h[i] += hIn[i]
    return h

@typechecked
def truncate(b:bytes_t(256)) -> digest_t:
    result: vlbytes_t = array.create(hashSize, uint8(0))
    for i in range(hashSize):
        result[i] = b[i]
    return digest_t((result))

@typechecked
def sha256(msg:vlbytes_t) -> digest_t:
    blocks : array(block_t)
    last : block_t
    blocks,last = array.split_blocks(msg, blockSize)
    nblocks : int = array.length(blocks)
    h:hash_t = h0
    for i in range(nblocks):
        h = compress(blocks[i],h)
    last_len : int = array.length(last)
    len_bits : int = array.length(msg) * 8
    pad: vlbytes_t = array.create(2*blockSize,uint8(0))
    pad[0:last_len] = last
    pad[last_len] = uint8(0x80)
    if last_len < blockSize - lenSize:
        pad[blockSize-lenSize:blockSize] = len_to_bytes(to_len(len_bits))
        h = compress(pad[0:blockSize],h)
    else:
        pad[(2*blockSize)-lenSize:2*blockSize] = len_to_bytes(to_len(len_bits))
        h = compress(pad[0:blockSize],h)
        h = compress(pad[blockSize:2*blockSize],h)
    result : bytes_t = words_to_bytes(h)
    return truncate(result)
