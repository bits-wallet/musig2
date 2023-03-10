//
//  wizdata.hpp
//  Bits
//
//  Created by Burak on 1.12.2022.
//

#ifndef wizdata_h
#define wizdata_h

#include <iostream>
#include <stdio.h>
#include <vector>
#include <cmath>
#include <sstream>
#include "uint256.h"
#include "crypto/common.h"


typedef std::vector<unsigned char> valtype;
typedef int64_t CAmount;

using Bytes = std::vector<uint8_t>;

class WizData {
public:
    static valtype splitValtypeSet(valtype *in, int startIndex, int size);
    static uint32_t varIntPrefixToUint32Len(valtype prefix);
    static valtype bufferAnySizeToValtype(unsigned char *buffer, int size);
    static valtype buffer32ToValtype(unsigned char *buffer);
    static valtype buffer80ToValtype(unsigned char *buffer);
    static uint256 *LEtoUint256(valtype in);
    static valtype *Uint16ToLE(uint16_t in);
    static valtype *Uint32ToLE(uint32_t in);
    static valtype *Uint64ToLE(uint64_t in);
    static uint8_t *LEtoUint8(valtype in);
    static uint16_t *LEtoUint16(valtype in);
    static uint32_t *LEtoUint32(valtype in);
    static uint64_t *LEtoUint64(valtype in);
    static valtype prefixCompactSizeCast(uint32_t size);
    static valtype charArrayToValtype(unsigned char* charArray, uint32_t size);
    static void valtypeToPointer(valtype val, unsigned char* pointer);
    
    static valtype hexStringToValtype(std::string const& hex);
    static std::string valtypeToHexString(valtype val);
};


#endif /* wizdata_h */
