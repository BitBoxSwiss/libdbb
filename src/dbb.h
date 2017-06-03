// Copyright (c) 2017 Shift Devices AG
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef LIBDBB_CRYPTO_SHA512_H
#define LIBDBB_CRYPTO_SHA512_H

#include <stdint.h>
#include <stdlib.h>

/** A hasher class for SHA-512. */
class DBB
{
private:
    uint64_t s[8];

public:
    DBB();
};

#endif // LIBDBB_CRYPTO_SHA512_H
