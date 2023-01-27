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
public:
    static uint256_t ec_scalar_add(uint256_t scalar1, uint256_t scalar2);
    static uint256_t ec_scalar_mul(uint256_t scalar1, uint256_t scalar2);
    static Point ec_point_add(Point point1, Point point2);
    static Point ec_point_mul(Point point, uint256_t scalar);
public:
    Point(point_t point_t): point(point_t) {};
    valtype xbytes();
    valtype ybytes();
    valtype cbytes();
    valtype ubytes();
    valtype cbytes_ext();
    bool has_even_y();
private:
    // secp256k1 point
    point_t point;
};

#endif /* point_h */
