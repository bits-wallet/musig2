//
//  main.cpp
//  musig2-cpp
//
//  Created by Burak on 22.01.2023.
//
#include <iostream>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "keygen_ctx.h"

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
    
    assert(secp256k1_tagged_sha256(context, hash32, tag, taglen, msg, msglen));
    
    return WizData::charArrayToValtype(hash32, 32);
}

valtype key_agg_coeff(secp256k1_context* context, std::vector<valtype> pubkeys, valtype pubkey){
    std::cout << "key_agg_coeff start" << std::endl;
    assert(pubkeys.size() > 1);
    
    valtype secondKey = WizData::hexStringToValtype("0000000000000000000000000000000000000000000000000000000000000000");
    
    for (int i = 1; i < pubkeys.size(); i++) {
        if(pubkeys[i] != pubkeys[0]){
            secondKey = pubkeys[i];
            break;
        }
    }
    
    if(pubkey == secondKey)
        return WizData::hexStringToValtype("0000000000000000000000000000000000000000000000000000000000000001");
        
    valtype L = hash_keys(context, pubkeys);
    
    unsigned char hash32[32];
    unsigned char tag[19] = "KeyAgg coefficient";
    
    valtype msg_;
    msg_.insert(msg_.begin(), L.begin(), L.end());
    msg_.insert(msg_.end(), pubkey.begin(), pubkey.end());
    
    size_t msglen = msg_.size();
    
    unsigned char msg[msg_.size()];
    std::copy(begin(msg_), end(msg_), msg);
    
    assert(secp256k1_tagged_sha256(context, hash32, tag, 18, msg, msglen));
    
    return WizData::charArrayToValtype(hash32, 32);
}

valtype key_agg(secp256k1_context* context, std::vector<valtype> pubkeys) {
    
    secp256k1_pubkey agg_key;
    
    for (int i = 0; i < pubkeys.size(); i++) {
        
        valtype coefficient = key_agg_coeff(context, pubkeys, pubkeys[i]);

        unsigned char tweak32[32];
        WizData::valtypeToPointer(coefficient, tweak32);
        
        unsigned char pubkey_input[33];
        WizData::valtypeToPointer(pubkeys[i], pubkey_input);

        secp256k1_pubkey secp256k1_publickey;
        
        assert(secp256k1_ec_pubkey_parse(context, &secp256k1_publickey, pubkey_input, 33));
        assert(secp256k1_ec_pubkey_tweak_mul(context, &secp256k1_publickey, tweak32));
        
        if(i == 0){
            agg_key = secp256k1_publickey;
        }
        else {
            secp256k1_pubkey* d[2];
            d[0] = &agg_key;
            d[1] = &secp256k1_publickey;
            secp256k1_pubkey new_aggkey;
            assert(secp256k1_ec_pubkey_combine(context, &new_aggkey, d, 2));
            agg_key = new_aggkey;
        }
    }
    unsigned char final_aggkey[33];
    size_t final_aggkey_size = 33;
    secp256k1_ec_pubkey_serialize(context, final_aggkey, &final_aggkey_size, &agg_key, SECP256K1_EC_COMPRESSED);
    valtype final_aggkey_valtype = WizData::charArrayToValtype(final_aggkey, 33);
    valtype aggkey_xonly;
    aggkey_xonly.insert(aggkey_xonly.begin(), final_aggkey_valtype.begin() + 1, final_aggkey_valtype.end());
    
    return aggkey_xonly;
}

int main(void) {
    unsigned char randomize[32];
    int return_val;

    
    
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (!fill_random(randomize, sizeof(randomize)))
        return 1;
    
    return_val = secp256k1_context_randomize(ctx, randomize);
    assert(return_val);
    
    valtype pubkey1 = WizData::hexStringToValtype("02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9");
    valtype pubkey2 = WizData::hexStringToValtype("03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659");
    valtype pubkey3 = WizData::hexStringToValtype("023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66");
    
    std::vector<valtype> pubkeys;
    pubkeys.push_back(pubkey1);
    pubkeys.push_back(pubkey1);
    pubkeys.push_back(pubkey2);
    pubkeys.push_back(pubkey2);
    
    valtype agg = key_agg(ctx, pubkeys);
    
    std::cout << "mama " << WizData::valtypeToHexString(agg) << std::endl;
   
    math::wide_integer::uintwide_t<512> a("0xF9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9");
    math::wide_integer::uintwide_t<512> b("0xDFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659");
    math::wide_integer::uintwide_t<512> c = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
    math::wide_integer::uintwide_t<256> d = (a*b) % c;
    
    std::stringstream mamas;
    mamas << std::hex << d;
    
    std::cout << "na " << mamas.str() << std::endl;
    
    return 0;
}
