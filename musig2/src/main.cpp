/*************************************************************************
 * Written in 2020-2022 by Elichai Turkel                                *
 * To the extent possible under law, the author(s) have dedicated all    *
 * copyright and related and neighboring rights to the software in this  *
 * file to the public domain worldwide. This software is distributed     *
 * without any warranty. For the CC0 Public Domain Dedication, see       *
 * EXAMPLES_COPYING or https://creativecommons.org/publicdomain/zero/1.0 *
 *************************************************************************/

#include <iostream>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_preallocated.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_recovery.h>
#include "random.h"
#include "hash.h"
#include "wizdata.h"

valtype hash_keys(secp256k1_context* context, std::vector<valtype> pubkeys){
    unsigned char hash32[32];
    unsigned char tag[12] = "KeyAgg list";
    size_t taglen = 11;
    
    valtype msg_;
    
    for(int i = 0; i < pubkeys.size(); i++){
        msg_.insert(msg_.end(), pubkeys[i].begin(), pubkeys[i].end());
    }
    size_t msglen = msg_.size();
    
    unsigned char msg[msg_.size()];
    std::copy(begin(msg_), end(msg_), msg);
    
    secp256k1_tagged_sha256(context, hash32, tag, taglen, msg, msglen);
    
    return *WizData::charArrayToValtype(hash32, 32);
    
}

valtype key_agg_coeff_internal(secp256k1_context* context, std::vector<valtype> pubkeys, valtype pubkey){
    assert(pubkeys.size() > 1);
    bool isSecond = (pubkeys[1] == pubkey);
    if(isSecond)
        return WizData::hexStringToValtype("0000000000000000000000000000000000000000000000000000000000000001");
        
    valtype L = hash_keys(context, pubkeys);
    
    unsigned char hash32[32];
    unsigned char tag[19] = "KeyAgg coefficient";
    size_t taglen = 18;
    
    valtype msg_;
    msg_.insert(msg_.begin(), L.begin(), L.end());
    msg_.insert(msg_.end(), pubkey.begin(), pubkey.end());
    
    size_t msglen = msg_.size();
    
    unsigned char msg[msg_.size()];
    std::copy(begin(msg_), end(msg_), msg);
    
    secp256k1_tagged_sha256(context, hash32, tag, taglen, msg, msglen);
    
    return *WizData::charArrayToValtype(hash32, 32);
}



int main(void) {
    
    unsigned char randomize[32];
    int return_val;

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (!fill_random(randomize, sizeof(randomize)))
        return 1;
    
    return_val = secp256k1_context_randomize(ctx, randomize);
    assert(return_val);

    return 0;
}
