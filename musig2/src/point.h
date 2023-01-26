//
//  point.h
//  musig2
//
//  Created by Burak on 26.01.2023.
//

#ifndef point_h
#define point_h

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
    valtype fullbytes();
    valtype cbytes();
    valtype cbytes_ext();
    bool has_even_y();
};

#endif /* point_h */
