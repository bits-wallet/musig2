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
    size_t taglen = 18;
    
    valtype msg_;
    msg_.insert(msg_.begin(), L.begin(), L.end());
    msg_.insert(msg_.end(), pubkey.begin(), pubkey.end());
    
    size_t msglen = msg_.size();
    
    unsigned char msg[msg_.size()];
    std::copy(begin(msg_), end(msg_), msg);
    
    secp256k1_tagged_sha256(context, hash32, tag, taglen, msg, msglen);
    
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
        size_t inputlen = 33;
        
        secp256k1_ec_pubkey_parse(context, &secp256k1_publickey, pubkey_input, inputlen);
        secp256k1_ec_pubkey_tweak_mul(context, &secp256k1_publickey, tweak32);
        
        if(i == 0){
            agg_key = secp256k1_publickey;
        }
        else {
            secp256k1_pubkey* d[2];
            d[0] = &agg_key;
            d[1] = &secp256k1_publickey;
            secp256k1_pubkey new_aggkey;
            secp256k1_ec_pubkey_combine(context, &new_aggkey, d, 2);
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
    
    std::cout << "kaka " << (int)agg[0] << std::endl;
    std::cout << "kaka " << (int)agg[1] << std::endl;
    std::cout << "kaka " << (int)agg[2] << std::endl;
    
    
    std::cout << "SCALAR arge " << std::endl;
    
    valtype mamma = WizData::hexStringToValtype("48c4");
    unsigned char ma[2];
    WizData::valtypeToPointer(mamma, ma);
    
    
    
    uint256 za;
    za.SetHex("48c480767da7f1395797e0755f0aedaebac4b24ee8d9be7dea715b61c37aa7aa");



    
    char mama[1];
    mama[0] = 12;
    
    math::wide_integer::uintwide_t<512> a = "0x4db67bcf877fafe2d498c979617e489f1744a246009c3a7d29201ac1adebcebb";
    math::wide_integer::uintwide_t<512> b = "0xf53303c7344599851a8dabd15bd8f4a311e15981e42c4c0c8f2748b205b5b24d";
    math::wide_integer::uintwide_t<512> c = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

    
    math::wide_integer::uintwide_t<512> d = (a + b) % c;
    
    std::string mamasstr;

    std::stringstream mamas;
    mamas << std::hex << d;

    mamasstr = mamas.str();
    
    std::cout << mamasstr << std::endl;
    std::cout << d << std::endl;
   
    

   

    
    
    return 0;
}
