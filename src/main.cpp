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

KeygenCtx key_agg(std::vector<valtype> pubkeys) {
    context_t *context = Point::create_context();
    
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
    return KeygenCtx(Point(agg_key), uint256_t(1), uint256_t(0));
}

std::string strPad256(std::string strIn) {
    std::string ret = strIn;
    for (int i = 0; i < 64; i++) {
        if(ret.size() < 64)
            ret = "0" + ret;
    }
    return ret;
}

KeygenCtx apply_tweak(KeygenCtx keygen_ctx, valtype tweak, bool x_only) {
    assert(tweak.size() == 32);
    
    uint256_t g(1);
    
    if(x_only && (!keygen_ctx.Q.has_even_y()))
        g = Point::curve_order -1;
    
    assert(uint256_t(("0x" + WizData::valtypeToHexString(tweak)).data()) < Point::curve_order);
    
    std::cout << "g is: " << g << std::endl;
    
    //Q dot g
    point_t Q_dot_g = keygen_ctx.Q.returnKey();
    
    std::stringstream g_ss;
    g_ss << std::hex << g;
    
    std::cout << "g is str: " << strPad256(g_ss.str()) << std::endl;
    
    unsigned char g_pointer[32];
    WizData::valtypeToPointer(WizData::hexStringToValtype(strPad256(g_ss.str())), g_pointer);
    
    assert(secp256k1_ec_pubkey_tweak_mul(Point::create_context(), &Q_dot_g, g_pointer));
    
    std::cout << "Q dot g: " << WizData::valtypeToHexString(Point(Q_dot_g).ubytes()) << std::endl;
    
    //G dot t
    secp256k1_pubkey G_dot_t;
    
    unsigned char tweak_pointer[32];
    WizData::valtypeToPointer(tweak, tweak_pointer);
    assert(secp256k1_ec_pubkey_create(Point::create_context(), &G_dot_t, tweak_pointer));
    
    std::cout << "G dot t: " << WizData::valtypeToHexString(Point(G_dot_t).ubytes()) << std::endl;
    
    
    //Q dot g plus G dot t
    point_t tweaked_Q;
    
    secp256k1_pubkey* points_to_add[2];
    points_to_add[0] = &Q_dot_g;
    points_to_add[1] = &G_dot_t;
    
    assert(secp256k1_ec_pubkey_combine(Point::create_context(), &tweaked_Q, points_to_add, 2));
    
    uint256_t tweak_int( ("0x" + strPad256(WizData::valtypeToHexString(tweak))).data());
    uint256_t new_gacc = Point::ec_scalar_mul(keygen_ctx.gacc, g);
    uint256_t new_tacc = Point::ec_scalar_add(Point::ec_scalar_mul(keygen_ctx.tacc, g), tweak_int);
    
    return KeygenCtx(Point(tweaked_Q), uint256_t(new_gacc), uint256_t(new_tacc));
}

int main(void) {
    valtype pubkey1 = WizData::hexStringToValtype("03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9");
    valtype pubkey2 = WizData::hexStringToValtype("02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9");
    valtype pubkey3 = WizData::hexStringToValtype("02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659");
    
    std::vector<valtype> pubkeys;
    pubkeys.push_back(pubkey2);
    pubkeys.push_back(pubkey3);
    pubkeys.push_back(pubkey1);
    
    KeygenCtx ehe = key_agg(pubkeys);
    
    std::cout << "agg xbytes: " << WizData::valtypeToHexString(ehe.Q.xbytes())  << std::endl;
    std::cout << "agg cbytes: " << WizData::valtypeToHexString(ehe.Q.cbytes())  << std::endl;
    std::cout << "agg ybytes: " << WizData::valtypeToHexString(ehe.Q.ybytes())  << std::endl;
    std::cout << "agg fullbytes: " << WizData::valtypeToHexString(ehe.Q.ubytes())  << std::endl;
    std::cout << "agg has even y: " << ehe.Q.has_even_y() << std::endl;
    
    KeygenCtx ehe2 = apply_tweak(ehe, WizData::hexStringToValtype("E8F791FF9225A2AF0102AFFF4A9A723D9612A682A25EBE79802B263CDFCD83BB"), true);
    
    std::cout << "tweaked: " << WizData::valtypeToHexString(ehe2.Q.ubytes()) << std::endl;
    std::cout << "gacc: " << ehe2.gacc << std::endl;
    std::cout << "tacc: " << ehe2.tacc << std::endl;

    
    return 0;
}
