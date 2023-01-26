//
//  musig2.h
//  musig2
//
//  Created by Burak on 26.01.2023.
//

#ifndef musig2_h
#define musig2_h

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

typedef math::wide_integer::uintwide_t<256> uint256_t;
typedef math::wide_integer::uintwide_t<512> uint512_t;
typedef secp256k1_context context_t;
typedef secp256k1_pubkey point_t;

class Point {
private:
    // secp256k1 context
    context_t *context;
    // secp256k1 point
    point_t point;
public:
    Point(point_t point_t);
    valtype xbytes();
    valtype ybytes();
    valtype cbytes();
    valtype cbytes_ext();
    bool has_even_y();
};

class KeygenCtx {
public:
    // The point Q representing the aggregate and potentially tweaked public key: an elliptic curve point
    Point Q;
    // The accumulated tweak tacc: an integer with 0 ≤ tacc < n
    uint256_t gacc;
    // The value gacc : 1 or -1 mod n
    uint256_t tacc;
    // KeygenCtx constructor
    KeygenCtx(Point Q_in, uint256_t gacc_in, uint256_t tacc_in): Q(Q_in), gacc(gacc_in), tacc(tacc_in) {};
};

#endif /* musig2_h */
