from hacspec.speclib import *
from wots import *
from sha256 import sha256

h : int = 10 # height -> number of signatures
n_keys : int = 2**h

n_bytes_t = bytes_t(n)
key2_t = bytes_t(2*n)
key3_t = bytes_t(3*n)
wots_keys_t = array_t(sk_t, n_keys)

# Private key:
# 2^h  WOTS+ private keys,
# idx (next WOTS+ sk),
# SK_PRF (n-bytes),
# root (n-bytes),
# public seed (n-bytes)
SK_t = tuple_t(wots_keys_t, nat_t, key_t, key_t, seed_t)

# Public key:
# algorithm oid (uint32_t),
# root node (n-bytes),
# seed (n-bytes)
PK_t = tuple_t(uint32_t, key_t, seed_t)

# Signature:
# idx_sig: WOTS+ key index (4 bytes)
# randomness r: byte string (n-bytes)
# sig_ots: WOTS+ signature (len * n bytes)
# auth: path (h * n bytes)
AUTH_PATH_t = array_t(key_t, h)
SIG_t = tuple_t(uint32_t, key_t, sig_t, AUTH_PATH_t)

@typechecked
def get_seed(sk: SK_t) -> seed_t:
    sks : wots_keys_t
    idx : nat_t
    prf_sk : key_t
    root : key_t
    public_seed : seed_t
    sks, idx, prf_sk, root, public_seed = sk
    return public_seed

# H: SHA2-256(toByte(1, 32) || KEY || M),
# H_msg: SHA2-256(toByte(2, 32) || KEY || M),

@typechecked
def H_msg(key: key3_t, m: vlbytes_t) -> digest_t:
    h_in : bytes_t = bytes.concat(key, m)
    # TODO: this is ugly
    return hash(bytes.from_nat_be(nat(2), nat(n)), array([]), h_in)


@typechecked
def H(key: key_t, m: key2_t) -> digest_t:
    return hash(bytes.from_nat_be(nat(1), nat(n)), key, m)

@typechecked
def get_wots_sk(k: SK_t, i: nat_t) -> sk_t:
    sks : wots_keys_t
    idx : nat_t
    prf_sk : key_t
    root : key_t
    public_seed : key_t
    sks, idx, prf_sk, root, public_seed = k
    return sks[i]

# Algorithm 7: RAND_HASH
#   Input:  n-byte value LEFT, n-byte value RIGHT, seed SEED,
#           address ADRS
#   Output: n-byte randomized hash
#
#   ADRS.setKeyAndMask(0);
#   KEY = PRF(SEED, ADRS);
#   ADRS.setKeyAndMask(1);
#   BM_0 = PRF(SEED, ADRS);
#   ADRS.setKeyAndMask(2);
#   BM_1 = PRF(SEED, ADRS);
#   return H(KEY, (LEFT XOR BM_0) || (RIGHT XOR BM_1));
@typechecked
def rand_hash(left: key_t, right: key_t, seed: seed_t, adr: address_t) -> digest_t:
    adr : address_t = set_key_and_mask(adr, uint32(0))
    key : digest_t = PRF(seed, adr)
    adr : address_t = set_key_and_mask(adr, uint32(1))
    bm_0 : digest_t = PRF(seed, adr)
    adr : address_t = set_key_and_mask(adr, uint32(2))
    bm_1 : digest_t = PRF(seed, adr)
    left_bm_o : digest_t = array.create(n, uint8(0))
    right_bm_1 : digest_t = array.create(n, uint8(0))
    for i in range(n):
        left_bm_o[i] = left[i] ^ bm_0[i]
        right_bm_1[i] = right[i] ^ bm_1[i]
    m : vlbytes_t = bytes.concat(left_bm_o, right_bm_1)
    r : digest_t = H(key, m)
    return r

# Algorithm 8: ltree
#   Input: WOTS+ public key pk, address ADRS, seed SEED
#   Output: n-byte compressed public key value pk[0]
#
#   unsigned int len' = len;
#   ADRS.setTreeHeight(0);
#   while ( len' > 1 ) {
#     for ( i = 0; i < floor(len' / 2); i++ ) {
#       ADRS.setTreeIndex(i);
#       pk[i] = RAND_HASH(pk[2i], pk[2i + 1], SEED, ADRS);
#     }
#     if ( len' % 2 == 1 ) {
#       pk[floor(len' / 2)] = pk[len' - 1];
#     }
#     len' = ceil(len' / 2);
#     ADRS.setTreeHeight(ADRS.getTreeHeight() + 1);
#   }
#   return pk[0];

@typechecked
def ltree(pk: pk_t, adr: address_t, seed: seed_t) -> key_t:
    l : int = uintn.to_int(length)
    adr : address_t = set_tree_height(adr, uint32(0))
    pk_i : pk_t = pk
    for _ in range(l):
        l_half : int = speclib.floor(l/2)
        for i in range(l_half):
            adr = set_tree_index(adr, uint32(i))
            pk_i[i] = rand_hash(pk_i[2*i], pk_i[2*i+1], seed, adr)
        if l % 2 == 1:
            pk_i[l_half] = pk_i[l-1]
        l = speclib.ceil(l/2)
        adr = set_tree_height(adr, get_tree_height(adr)+uint32(1))
        if l <= 1:
            # TODO: this is necessary because we simulate while l > 1 here.
            break
    return pk_i[0]

# Algorithm 9: treeHash
#   Input: XMSS private key SK, start index s, target node height t,
#          address ADRS
#   Output: n-byte root node - top node on Stack
#
#   if( s % (1 << t) != 0 ) return -1;
#   for ( i = 0; i < 2^t; i++ ) {
#     SEED = getSEED(SK);
#     ADRS.setType(0);   // Type = OTS hash address
#     ADRS.setOTSAddress(s + i);
#     pk = WOTS_genPK (getWOTS_SK(SK, s + i), SEED, ADRS);
#     ADRS.setType(1);   // Type = L-tree address
#     ADRS.setLTreeAddress(s + i);
#     node = ltree(pk, SEED, ADRS);
#     ADRS.setType(2);   // Type = hash tree address
#     ADRS.setTreeHeight(0);
#     ADRS.setTreeIndex(i + s);
#     while ( Top node on Stack has same height t' as node ) {
#        ADRS.setTreeIndex((ADRS.getTreeIndex() - 1) / 2);
#        node = RAND_HASH(Stack.pop(), node, SEED, ADRS);
#        ADRS.setTreeHeight(ADRS.getTreeHeight() + 1);
#     }
#     Stack.push(node);
#   }
#   return Stack.pop();

@typechecked
def tree_hash(sk: SK_t, s: uint32_t, t: uint32_t, adr: address_t) -> key_t:
    x: int = uint32.to_int(s) % (1 << uintn.to_int(t))
    if x != 0:
        fail("Invalid parameters to tree hash.")
    offset: int = 0
    stack: array_t = array.create(2**uint32.to_int(t), array.create(n, uint8(0)))
    for i in range(2**uint32.to_int(t)):
        seed: seed_t = get_seed(sk) # FIXME
        adr: address_t = set_type(adr, uint32(0))
        a: uint32_t = s + uint32(i)
        adr = set_ots_address(adr, a)
        pk: pk_t
        pk, _ = key_gen_pk(adr, seed, get_wots_sk(sk, uint32.to_int(a)))
        adr = set_type(adr, uint32(1))
        adr = set_ltree_address(adr, a)
        node: key_t = ltree(pk, adr, seed)
        adr = set_type(adr, uint32(2))
        adr = set_tree_height(adr, uint32(0))
        adr = set_tree_index(adr, a)
        if offset > 1:
            for _ in range(uint32.to_int(t)): # The stack has at most t-1 elements.
                new_index: uint32_t = uint32(uint32.to_int(get_tree_index(adr)) - 1 // 2)
                adr = set_tree_index(adr, new_index)
                node = rand_hash(stack[offset-1], node, seed, adr)
                adr = set_tree_height(adr, get_tree_height(adr) + uint32(1))
        stack[offset] = node
        offset += 1

# Algorithm 10: XMSS_keyGen - Generate an XMSS key pair
#   Input: No input
#   Output: XMSS private key SK, XMSS public key PK
#
#   // Example initialization for SK-specific contents
#   idx = 0;
#   for ( i = 0; i < 2^h; i++ ) {
#     wots_sk[i] = WOTS_genSK();
#   }
#   initialize SK_PRF with a uniformly random n-byte string;
#   setSK_PRF(SK, SK_PRF);
#
#   // Initialization for common contents
#   initialize SEED with a uniformly random n-byte string;
#   setSEED(SK, SEED);
#   setWOTS_SK(SK, wots_sk));
#   ADRS = toByte(0, 32);
#   root = treeHash(SK, 0, h, ADRS);
#
#   SK = idx || wots_sk || SK_PRF || root || SEED;
#   PK = OID || root || SEED;
#   return (SK || PK);

@typechecked
def key_gen_xmss() -> tuple_t(SK_t, PK_t):
    zero_key: sk_t = sk_t.create(uintn.to_int(length), key_t.create(n, uint8(0)))
    wots_keys: wots_keys_t = wots_keys_t.create(n_keys, zero_key)
    for i in range(n_keys):
        wots_sk : sk_t = key_gen_sk()
        wots_keys[i] = wots_sk
    idx: nat_t = 0
    SK_PRF: key_t = bytes.create_random_bytes(n)
    seed: seed_t = bytes.create_random_bytes(n)
    adr: address_t = array.create(8, uint32(0))
    dummy_root: key_t = array.create(n, uint8(0))
    xmss_sk_tmp: SK_t = (wots_keys, idx, SK_PRF, dummy_root, seed)
    root : key_t = tree_hash(xmss_sk_tmp, uint32(0), uint32(h), adr)
    xmss_sk: SK_t = (wots_keys, idx, SK_PRF, root, seed)
    xmss_pk: PK_t = (uint32(0), root, seed)
    return xmss_sk, xmss_pk

# Algorithm 11: treeSig - Generate a WOTS+ signature on a message with
#                         corresponding authentication path
#   Input: n-byte message M', XMSS private key SK,
#          signature index idx_sig, ADRS
#   Output: Concatenation of WOTS+ signature sig_ots and
#           authentication path auth
#
#   auth = buildAuth(SK, idx_sig, ADRS);
#   ADRS.setType(0);   // Type = OTS hash address
#   ADRS.setOTSAddress(idx_sig);
#   sig_ots = WOTS_sign(getWOTS_SK(SK, idx_sig),
#                       M', getSEED(SK), ADRS);
#   Sig = sig_ots || auth;
#   return Sig;

# TODO

# Algorithm 12: XMSS_sign - Generate an XMSS signature and update the
#                           XMSS private key
#   Input: Message M, XMSS private key SK
#   Output: Updated SK, XMSS signature Sig
#
#   idx_sig = getIdx(SK);
#   setIdx(SK, idx_sig + 1);
#   ADRS = toByte(0, 32);
#   byte[n] r = PRF(getSK_PRF(SK), toByte(idx_sig, 32));
#   byte[n] M' = H_msg(r || getRoot(SK) || (toByte(idx_sig, n)), M);
#   Sig = idx_sig || r || treeSig(M', SK, idx_sig, ADRS);
#   return (SK || Sig);

# TODO

# Algorithm 13: XMSS_rootFromSig - Compute a root node from a tree
#                                  signature
#   Input: index idx_sig, WOTS+ signature sig_ots, authentication path
#          auth, n-byte message M', seed SEED, address ADRS
#   Output: n-byte root value node[0]
#
#   ADRS.setType(0);   // Type = OTS hash address
#   ADRS.setOTSAddress(idx_sig);
#   pk_ots = WOTS_pkFromSig(sig_ots, M', SEED, ADRS);
#   ADRS.setType(1);   // Type = L-tree address
#   ADRS.setLTreeAddress(idx_sig);
#   byte[n][2] node;
#   node[0] = ltree(pk_ots, SEED, ADRS);
#   ADRS.setType(2);   // Type = hash tree address
#   ADRS.setTreeIndex(idx_sig);
#   for ( k = 0; k < h; k++ ) {
#     ADRS.setTreeHeight(k);
#     if ( (floor(idx_sig / (2^k)) % 2) == 0 ) {
#       ADRS.setTreeIndex(ADRS.getTreeIndex() / 2);
#       node[1] = RAND_HASH(node[0], auth[k], SEED, ADRS);
#     } else {
#       ADRS.setTreeIndex((ADRS.getTreeIndex() - 1) / 2);
#       node[1] = RAND_HASH(auth[k], node[0], SEED, ADRS);
#     }
#     node[0] = node[1];
#   }
#   return node[0];

@typechecked
def root_from_sig(idx_sig: uint32_t, sig_ots: sig_t, auth_path: AUTH_PATH_t,
                  m: n_bytes_t, seed: seed_t, adr: address_t) -> key_t:
    adr: address_t = set_type(adr, uint32(0))
    adr = set_ots_address(adr, idx_sig)
    pk_ots: pk_t
    adr2: address_t
    pk_ots, adr2 = wots_pk_from_sig(m, sig_ots, adr, seed)

    adr = set_type(adr, uint32(1))
    adr = set_ltree_address(adr, idx_sig)
    node_0: key_t = ltree(pk_ots, adr, seed)

    adr = set_type(adr, uint32(2))
    adr = set_tree_index(adr, idx_sig)
    for k in range(h):
        node_1: key_t
        adr = set_tree_height(adr, uint32(k))
        if (speclib.floor(uintn.to_int(idx_sig) / (2 ** k)) % 2) == 0:
            adr = set_tree_index(adr, uint32(uintn.to_int(get_tree_index(adr)) // 2))
            node_1 = rand_hash(node_0, auth_path[k], seed, adr)
        else:
            adr = set_tree_index(adr, uint32((uintn.to_int(get_tree_index(adr)) - 1) // 2))
            node_1 = rand_hash(auth_path[k], node_0, seed, adr)
        node_0 = node_1
    return node_0

# Algorithm 14: XMSS_verify - Verify an XMSS signature using the
#                             corresponding XMSS public key and a message
#   Input: XMSS signature Sig, message M, XMSS public key PK
#   Output: Boolean
#
#   ADRS = toByte(0, 32);
#   byte[n] M' = H_msg(r || getRoot(PK) || (toByte(idx_sig, n)), M);
#
#   byte[n] node = XMSS_rootFromSig(idx_sig, sig_ots, auth, M',
#                                   getSEED(PK), ADRS);
#   if ( node == getRoot(PK) ) {
#     return true;
#   } else {
#     return false;
#   }

@typechecked
def xmss_verify(sig: SIG_t, m: vlbytes_t, pk: PK_t) -> bool:
    adr: address_t = array.create(8, uint32(0))
    idx_sig: uint32_t
    r: key_t
    sig_ots: sig_t
    auth_path: AUTH_PATH_t
    idx_sig, r, sig_ots, auth_path = sig
    oid: uint32_t
    root_node: key_t
    seed: seed_t
    oid, root_node, seed = pk
    h_k: vlbytes_t = array.concat(r, root_node)
    idx_sig_bytes_tmp: bytes_t = bytes.from_uint32_be(idx_sig)
    # pad idx_sig_bytes with 0s up to n
    # TODO: make this nicer
    idx_sig_bytes: bytes_t = bytes.create(n, uint8(0))
    for i in range(array.length(idx_sig_bytes_tmp)):
        idx_sig_bytes[i] = idx_sig_bytes_tmp[i]
    h_k = array.concat(h_k, idx_sig_bytes)

    m2: digest_t = H_msg(h_k, m)
    node: digest_t = root_from_sig(idx_sig, sig_ots, auth_path, m2, seed, adr)

    return node == root_node
