/*
hash.c version 20160210
Andreas Hülsing
Joost Rijneveld
Public domain.
*/

/*
 * Used in hash.c
 */
#define SET_BLOCK_BIT(a, b) (a[15] = (a[15] & 1) | ((b << 1) & 2))
#define SET_KEY_BIT(a, b) (a[15] = (a[15] & 2) | (b & 1))

#define WOTS_SELECT_KEY(a) (a[15] = 1)
#define WOTS_SELECT_BLOCK(a) (a[15] = 0)
/*
 * Used in wots.c
 */
#define SET_HASH_ADDRESS(a, v) {\
  a[14] = (v & 255);}

#define SET_CHAIN_ADDRESS(a, v) {\
  a[13] = (v & 255);\
  a[12] = ((v >> 8) & 255);}

/*
 * Used in xmss_fast.c and xmss.c
 */
#define SET_LAYER_ADDRESS(a, v) {\
  a[0] = (v & 255);}
  
#define SET_TREE_ADDRESS(a, v) {\
  a[5] = (v & 255);\
  a[4] = (v >> 8) & 255;\
  a[3] = (v >> 16) & 255;\
  a[2] = (v >> 24) & 255;\
  a[1] = (v >> 32) & 255;}

#define SET_OTS_BIT(a, b) {\
  a[6] = (b & 1);\
  a[7] = 0;\
  a[8] = 0;}

#define SET_OTS_ADDRESS(a, v) {\
  a[11] = (v & 255);\
  a[10] = (v >> 8) & 255;\
  a[9] = (v >> 16) & 255;}

#define ZEROISE_OTS_ADDR(a) {\
  a[12] = 0;\
  a[13] = 0;\
  a[14] = 0;\
  a[15] = 0;}

#define SET_LTREE_BIT(a, b) {\
  a[7] = (a[7] & 0) | (b & 1);}

#define SET_LTREE_ADDRESS(a, v) {\
  a[10] = v & 255;\
  a[9] = (v >> 8) & 255;\
  a[8] = (v >> 16) & 255;}

#define SET_LTREE_TREE_HEIGHT(a, v) {\
  a[11] = (v & 255);}

#define SET_LTREE_TREE_INDEX(a, v) {\
  a[14] = (v & 255);\
  a[13] = (v >> 8) & 255;\
  a[12] = (v >> 16) & 3;}

#define SET_NODE_PADDING(a) {\
  a[8] = 0;\
  a[9] = 0;\
  a[10] = 0;}

#define SET_NODE_TREE_HEIGHT(a, v) {\
  a[11] = (v & 255);}

#define SET_NODE_TREE_INDEX(a, v) {\
  a[14] = v & 255;\
  a[13] = (v >> 8) & 255;\
  a[12] = (v >> 16) & 255;}

