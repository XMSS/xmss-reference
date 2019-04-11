from hacspec.speclib import *
from sha256 import sha256

# Influences signature length, not security
w_four : uint32_t = uint32(4)
w_sixteen : uint32_t = uint32(16)


# Parameters
# n := length (message, signature, key), SHA2 output length
n : int = 32
w : uint32_t = w_sixteen
log_w : int = speclib.log(uint32.to_int(w), 2)

length1 : uint32_t = uint32(speclib.ceil(8*n / log_w))
tmp : int = uint32.to_int(length1) * (uint32.to_int(w) - 1)
tmp = speclib.log(tmp, 2)
length2 : uint32_t = uint32(int(tmp // log_w + 1))
length : uint32_t = length1 + length2

# Types


key_t = bytes_t(n)
sk_t = array_t(key_t, uint32.to_int(length))
pk_t = array_t(key_t, uint32.to_int(length))
sig_t = array_t(key_t, uint32.to_int(length))
address_t = array_t(uint32_t, 8)
key_pair_t = tuple_t(sk_t, pk_t, address_t)
digest_t = bytes_t(32)
seed_t = bytes_t(n)
chain_t = tuple_t(address_t, vlbytes_t)

# F: SHA2-256(toByte(0, 32) || KEY || M),
# PRF: SHA2-256(toByte(3, 32) || KEY || M).


@typechecked
def hash(prefix: key_t, key: key_t, m: vlbytes_t) -> digest_t:
    h_in : bytes_t = bytes.concat(prefix, key)
    h_in = bytes.concat(h_in, m)
    return sha256(bytes(h_in))


@typechecked
def F(key: key_t, m: vlbytes_t) -> digest_t:
    return hash(bytes.from_nat_be(nat(0), nat(32)), key, m)


@typechecked
def PRF(key: key_t, m: address_t) -> digest_t:
    m_ : address_t = bytes.from_uint32_be(m[0])
    m_ = bytes.concat(m_, bytes.from_uint32_be(m[1]))
    m_ = bytes.concat(m_, bytes.from_uint32_be(m[2]))
    m_ = bytes.concat(m_, bytes.from_uint32_be(m[3]))
    m_ = bytes.concat(m_, bytes.from_uint32_be(m[4]))
    m_ = bytes.concat(m_, bytes.from_uint32_be(m[5]))
    m_ = bytes.concat(m_, bytes.from_uint32_be(m[6]))
    m_ = bytes.concat(m_, bytes.from_uint32_be(m[7]))
    return hash(bytes.from_nat_be(nat(3), nat(32)), key, m_)


# Address is a 32-byte array with the following definition
# 4-byte: layer address
# 8-byte: tree address
# 4-byte: type: 0 for OTS, 1 for L-tree, 2 for hash tree
# 4-byte: OTS address, L-tree address, padding (0)
# 4-byte: chain address, tree height
# 4-byte: hash address, tree index
# 4-byte: key and mask

@typechecked
def set_type(adr: address_t, t: uint32_t) -> address_t:
    result : address_t = array.copy(adr)
    result[3] = t
    return result


@typechecked
def set_ots_address(adr: address_t, ots_adr: uint32_t) -> address_t:
    result : address_t = array.copy(adr)
    result[-4] = ots_adr
    return result


@typechecked
def set_ltree_address(adr: address_t, ltree_adr: uint32_t) -> address_t:
    return set_ots_address(adr, ltree_adr)


@typechecked
def set_chain_address(adr: address_t, h_adr: uint32_t) -> address_t:
    result : address_t = array.copy(adr)
    result[-3] = h_adr
    return result


@typechecked
def set_tree_height(adr: address_t, h: uint32_t) -> address_t:
    return set_chain_address(adr, h)


@typechecked
def get_tree_height(adr: address_t) -> uint32_t:
    return adr[-3]


@typechecked
def set_hash_address(adr: address_t, h_adr: uint32_t) -> address_t:
    result : address_t = array.copy(adr)
    result[-2] = h_adr
    return result


@typechecked
def set_tree_index(adr: address_t, i: uint32_t) -> address_t:
    return set_hash_address(adr, i)


@typechecked
def get_tree_index(adr: address_t) -> uint32_t:
    return adr[-2]


@typechecked
def set_key_and_mask(adr: address_t, kam: uint32_t) -> address_t:
    result : address_t = array.copy(adr)
    result[-1] = kam
    return result

# Input: Input string X, start index i, number of steps s, seed SEED, address ADRS
# Output: value of F iterated s times on X


@typechecked
def wots_chain(x: bytes_t, start: int, steps: int, seed: seed_t, adr: address_t) -> chain_t:
    hmo = bytes.copy(x)
    adr : address_t
    for i in range(start + steps):
        if i >= start:
            # TODO: This is a hack because hacspec currently doesn't allow range(min, max)
            adr = set_hash_address(adr, uint32(i))
            adr = set_key_and_mask(adr, uint32(0))
            key : digest_t = PRF(seed, adr)
            adr = set_key_and_mask(adr, uint32(1))
            bm : digest_t = PRF(seed, adr)
            fin = bytes([])
            for (a, b) in array.zip(hmo, bm):
                fin = bytes.concat(fin, bytes([a ^ b]))
            hmo = F(key, fin)
    return adr, hmo


@typechecked
def key_gen_sk() -> sk_t:
    sk : sk_t = sk_t.create(uintn.to_int(length), key_t.create(n, uint8(0)))
    for i in range(uint32.to_int(length)):
        sk_i: bytes_t = bytes.create_random_bytes(n)
        sk[i] = sk_i
    return sk

@typechecked
def key_gen_pk(adr: address_t, seed: seed_t, sk: sk_t) -> tuple_t(pk_t, address_t):
    pk : pk_t = pk_t.create(uintn.to_int(length), key_t.create(n, uint8(0)))
    pk_i : vlbytes_t
    for i in range(uint32.to_int(length)):
        adr : address_t = set_chain_address(adr, uint32(i))
        adr, pk_i = wots_chain(sk[i], 0, uint32.to_int(w)-1, seed, adr)
        pk[i] = pk_i
    return (pk, adr)

@typechecked
def key_gen(adr: address_t, seed: seed_t) -> key_pair_t:
    sk : sk_t = key_gen_sk()
    pk : pk_t
    adr_out : address_t
    pk, adr_out = key_gen_pk(adr, seed, sk)
    return (sk, pk, adr_out)


@typechecked
def base_w(msg: vlbytes_t, l: uint32_t) -> vlbytes_t:
    i : int = 0
    out : int = 0
    total : int = 0
    bits : int = 0
    basew : vlbytes_t = bytes([])
    for consumed in range(uint32.to_int(l)):
        if bits == 0:
            total = uint8.to_int(msg[i])
            i = i + 1
            bits = bits + 8
        bits = bits - int(log_w)
        bw : int = (total >> bits) & int(uint32.to_int(w) - 1)
        basew = array.concat(basew, bytes([uint8(bw)]))
        out = out + 1
    return basew

@typechecked
def wots_msg(msg: vlbytes_t) -> vlbytes_t:
    csum : int = 0
    m : vlbytes_t = base_w(msg, length1)
    for i in range(uint32.to_int(length1)):
        csum = csum + uint32.to_int(w) - 1 - uint32.to_int(m[i])
    csum = nat(csum << int(8 - ((uint32.to_int(length2) * log_w) % 8)))
    length2_bytes : nat_t = speclib.ceil((uint32.to_int(length2) * log_w) // 8)
    csum_bytes : bytes_t = bytes.from_nat_be(csum, length2_bytes)
    m : bytes_t = array.concat(m, base_w(csum_bytes, length2))
    return m


@typechecked
def wots_sign(msg: vlbytes_t, sk: sk_t, adr: address_t, seed: seed_t) -> sig_t:
    m : vlbytes_t = wots_msg(msg)
    sig : sig_t = sig_t.create(uintn.to_int(length), key_t.create(n, uint8(0)))
    for i in range(uint32.to_int(length)):
        adr : address_t = set_chain_address(adr, uint32(i))
        sig_i : vlbytes_t
        adr, sig_i = wots_chain(sk[i], 0, uint32.to_int(m[i]), seed, adr)
        sig[i] = sig_i
    return sig


@typechecked
def wots_pk_from_sig(msg: vlbytes_t, sig: sig_t, adr: address_t, seed: seed_t) -> tuple_t(pk_t, address_t):
    m : vlbytes_t = wots_msg(msg)
    pk2 : pk_t = pk_t.create(uintn.to_int(length), key_t.create(n, uint8(0)))
    for i in range(uint32.to_int(length)):
        adr : address_t = set_chain_address(adr, uint32(i))
        m_i : int = uint32.to_int(m[i])
        pk_i : vlbytes_t
        adr, pk_i = wots_chain(sig[i], m_i, uint32.to_int(w) - 1 - m_i, seed, adr)
        pk2[i] = pk_i
    return (pk2, adr)


@typechecked
def wots_verify(pk: pk_t, msg: digest_t, sig: sig_t, adr: address_t, seed: seed_t) -> bool:
    pk2: pk_t
    adr2: address_t
    pk2, adr2 = wots_pk_from_sig(msg, sig, adr, seed)
    return pk == pk2

