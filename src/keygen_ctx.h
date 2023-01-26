//
//  keygen_ctx.h
//  musig2
//
//  Created by Burak on 26.01.2023.
//

#ifndef keygen_ctx_h
#define keygen_ctx_h

#include <stdio.h>
#include "point.h"

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

#endif /* keygen_ctx_h */
