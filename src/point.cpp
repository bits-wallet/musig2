//
//  point.cpp
//  musig2
//
//  Created by Burak on 26.01.2023.
//

#include "point.h"

// secp256k1 curve field
uint256_t curve_field = std::string("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F").data();

// secp256k1 curve order
uint256_t curve_order = std::string("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141").data();

context_t* Point::create_context(){
    unsigned char randomize[32];
    int return_val;
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    assert(fill_random(randomize, sizeof(randomize)));
    return_val = secp256k1_context_randomize(ctx, randomize);
    assert(return_val);
    return ctx;
}

uint256_t Point::ec_scalar_add(uint256_t scalar1, uint256_t scalar2) {
    return uint256_t((uint512_t(scalar1) + uint512_t(scalar2)) % uint512_t(curve_order));
}

uint256_t Point::ec_scalar_mul(uint256_t scalar1, uint256_t scalar2) {
    return uint256_t((uint512_t(scalar1) * uint512_t(scalar2)) % uint512_t(curve_order));
}

Point Point::ec_point_add(Point point1, Point point2) {
    secp256k1_pubkey* d[2];
    d[0] = &(point1.point);
    d[1] = &(point2.point);
    point_t out;
    assert(secp256k1_ec_pubkey_combine(create_context(), &out, d, 2));
    
    return Point(out);
}

Point Point::ec_point_mul(Point point, uint256_t scalar) {
    point_t out = point.point;

    std::stringstream scalar_ss;
    scalar_ss << std::hex << scalar;
    
    valtype scalar_val = WizData::hexStringToValtype(scalar_ss.str());
    unsigned char scalar_p[32];
    WizData::valtypeToPointer(scalar_val, scalar_p);
    
    assert(secp256k1_ec_pubkey_tweak_mul(create_context(), &out, scalar_p));
    
    return Point(out);
}

valtype Point::cbytes() {
    unsigned char cbytes[33];
    size_t outputlen = 33;
    assert(secp256k1_ec_pubkey_serialize(create_context(), cbytes, &outputlen, &(this->point), SECP256K1_EC_COMPRESSED));
    valtype cbytes_val = WizData::charArrayToValtype(cbytes, 33);
    return cbytes_val;
}

valtype Point::ubytes() {
    unsigned char fullbytes[65];
    size_t outputlen = 65;
    assert(secp256k1_ec_pubkey_serialize(create_context(), fullbytes, &outputlen, &(this->point), SECP256K1_EC_UNCOMPRESSED));
    valtype fullbytes_val = WizData::charArrayToValtype(fullbytes, 65);
    return fullbytes_val;
}

valtype Point::xbytes() {
    valtype xbytes_val;
    valtype cbytes_val = this->cbytes();
    xbytes_val.insert(xbytes_val.begin(), cbytes_val.begin() + 1, cbytes_val.end());
    return xbytes_val;
}

valtype Point::ybytes() {
    valtype fullbytes_val = this->ubytes();
    valtype ybytes_val;
    ybytes_val.insert(ybytes_val.begin(), fullbytes_val.begin() + 33, fullbytes_val.end());
    return ybytes_val;
}

bool Point::has_even_y() {
    return (uint256_t(std::string("0x" + WizData::valtypeToHexString(this->ybytes())).data()) % 2 == 0);
}
