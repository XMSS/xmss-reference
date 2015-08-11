#define TREE_HEIGHT 10
#define WOTS_LOGW 4 // -> w = 16

#define SK_RAND_SEED_BYTES 32
#define MESSAGE_HASH_SEED_BYTES 32

#define WOTS_W (1 << WOTS_LOGW)
#define WOTS_L1 ((256+WOTS_LOGW-1)/WOTS_LOGW)
#define WOTS_L 67  // for WOTS_W == 16
#define WOTS_LOG_L 7  // for WOTS_W == 16
#define WOTS_SIGBYTES (WOTS_L*HASH_BYTES)

#define HASH_BYTES 32 
