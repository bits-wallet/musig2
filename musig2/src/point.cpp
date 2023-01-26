//
//  point.cpp
//  musig2
//
//  Created by Burak on 26.01.2023.
//

#include "point.h"

Point::Point(point_t point_t) {
    unsigned char randomize[32];
    int return_val;
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    assert(fill_random(randomize, sizeof(randomize)));
    return_val = secp256k1_context_randomize(ctx, randomize);
    assert(return_val);
    
    this->context = ctx;
    this->point = point_t;
}

valtype Point::cbytes() {
    unsigned char cbytes[33];
    size_t outputlen = 33;
    assert(secp256k1_ec_pubkey_serialize(this->context, cbytes, &outputlen, &(this->point), SECP256K1_EC_COMPRESSED));
    valtype cbytes_val = WizData::charArrayToValtype(cbytes, 33);
    return cbytes_val;
}

valtype Point::xbytes() {
    valtype xbytes_val;
    valtype cbytes_val = this->cbytes();
    xbytes_val.insert(xbytes_val.begin(), cbytes_val.begin() + 1, cbytes_val.end());
    return xbytes_val;
}

valtype Point::fullbytes() {
    unsigned char fullbytes[65];
    size_t outputlen = 65;
    assert(secp256k1_ec_pubkey_serialize(this->context, fullbytes, &outputlen, &(this->point), SECP256K1_EC_UNCOMPRESSED));
    valtype fullbytes_val = WizData::charArrayToValtype(fullbytes, 65);
    return fullbytes_val;
}

valtype Point::ybytes() {
    valtype fullbytes_val = this->fullbytes();
    valtype ybytes_val;
    ybytes_val.insert(ybytes_val.begin(), fullbytes_val.begin() + 33, fullbytes_val.end());
    return ybytes_val;
}

bool Point::has_even_y() {
    return (uint256_t(std::string("0x" + WizData::valtypeToHexString(this->ybytes())).data()) % 2 == 0);
}
