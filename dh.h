/*  RTMPDump - Diffie-Hellmann Key Exchange
 *  Copyright (C) 2009 Andrej Stepanchuk
 *  Copyright (C) 2009 Howard Chu
 *
 *  This Program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This Program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with RTMPDump; see the file COPYING.  If not, write to
 *  the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *  http://www.gnu.org/copyleft/gpl.html
 *
 */

#include <openssl/bn.h>
#include <openssl/dh.h>

#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rc4.h>

#include "bytes.h"

#ifdef __cplusplus
extern "C" {
#endif
int isValidPublicKey(BIGNUM *y, BIGNUM *p, BIGNUM *q);
DH* DHInit(int nKeyBits);
int DHGenerateKey(DH *dh);
int DHGetPublicKey(DH *dh, uint8_t *pubkey, size_t nPubkeyLen);
int DHGetPrivateKey(DH *dh, uint8_t *privkey, size_t nPrivkeyLen);
int DHComputeSharedSecretKey(DH *dh, uint8_t *pubkey, size_t nPubkeyLen, uint8_t *secret);
void DHFree(DH *dh);
#ifdef __cplusplus
}
#endif
