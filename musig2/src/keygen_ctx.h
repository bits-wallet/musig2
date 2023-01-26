//
//  keygen_ctx.h
//  musig2
//
//  Created by Burak on 26.01.2023.
//

#ifndef keygen_ctx_h
#define keygen_ctx_h

#include <stdio.h>
#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_preallocated.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_recovery.h>
#include "random.h"
#include "hash.h"
#include "wizdata.h"
#include "uintwide_t.h"
#include "keygen_ctx.h"

typedef math::wide_integer::uintwide_t<256> uint256_t;
typedef math::wide_integer::uintwide_t<512> uint512_t;

class KeygenCtx {
public:
    // The point Q representing the aggregate and potentially tweaked public key: an elliptic curve point
    secp256k1_pubkey Q;
    // The accumulated tweak tacc: an integer with 0 ≤ tacc < n
    uint256_t gacc;
    // The value gacc : 1 or -1 mod n
    uint256_t tacc;
    // KeygenCtx constructor
    KeygenCtx(secp256k1_pubkey Q_in, uint256_t gacc_in, uint256_t tacc_in): Q(Q_in), gacc(gacc_in), tacc(tacc_in) {};
};

#endif /* keygen_ctx_h */
