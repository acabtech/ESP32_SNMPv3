// Crypto digest — crypto_soft.h companion (reference backend).
//
// SPDX-License-Identifier: GPL-3.0
#ifndef CRYPTO_SOFT_H
#define CRYPTO_SOFT_H

// Re-export the interface; tests link against this implementation instead of
// the mbedtls backend.
#include "crypto.h"

#endif  // CRYPTO_SOFT_H