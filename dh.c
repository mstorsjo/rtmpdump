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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <limits.h>

#include "log.h"
#include "dh.h"
#include "dhgroups.h"

/*
BIGNUM *dh_shared_p = 0; // shared prime
BIGNUM *dh_shared_g = 0; // shared base

void dh_pg_init()
{
	if(dh_shared_p || dh_shared_g)
		return;
	
	dh_shared_p = BN_new();
	dh_shared_g = BN_new();
	assert(dh_shared_p && dh_shared_g);

	int res = BN_hex2bn(&dh_shared_p, P1024);	// prime P1024, see dhgroups.h
	assert(res);

	res = BN_set_word(dh_shared_g, 2);		// base 2
	assert(res);
}
*/

// RFC 2631, Section 2.1.5, http://www.ietf.org/rfc/rfc2631.txt
int isValidPublicKey(BIGNUM *y, BIGNUM *p , BIGNUM *q)
{
	assert(y);

	BIGNUM *bn = BN_new();
	assert(bn);

	// y must lie in [2,p-1]
	BN_set_word(bn,1);
	if(BN_cmp(y,bn) < 0) {
		Log(LOGWARNING, "DH public key must be at least 2");
		goto failed;
	}

	// bn = p-2
	BN_copy(bn, p);
	BN_sub_word(bn, 1);
	if(BN_cmp(y,bn) > 0) {
		Log(LOGWARNING, "DH public key must be at most p-2");
		goto failed;
	}

	// Verify with Sophie-Germain prime
	//
	// This is a nice test to make sure the public key position is calculated
	// correctly. This test will fail in about 50% of the cases if applied to 
	// random data.
	//
	if(q) {
		// y must fulfill y^q mod p = 1
		BN_CTX *ctx = BN_CTX_new();
		BN_mod_exp(bn, y, q, p, ctx);

		//BIGNUM *one = BN_new();
		//BN_one(one);

		if(BN_cmp(bn, BN_value_one()) != 0) {
			Log(LOGWARNING, "DH public key does not fulfill y^q mod p = 1");
			BN_CTX_free(ctx);
			//goto failed;
		}
		//BN_CTX_free(ctx);
	} //*/

	BN_free(bn);

	return 1;
failed:
	//Log(LOGDEBUG, "Insecure DH public key: %s", BN_bn2hex(y));
	BN_free(bn);
	return 0;
}

DH* DHInit(int nKeyBits)
{
	int res;
	DH* dh = DH_new();

	if(!dh)
		goto failed;

	dh->p = BN_new();
	dh->g = BN_new();

	if(!dh->p || !dh->g)
		goto failed;

        res = BN_hex2bn(&dh->p, P1024); // prime P1024, see dhgroups.h
        if(!res) { goto failed; }

        res = BN_set_word(dh->g, 2);    // base 2
        if(!res) { goto failed; }

	dh->length = nKeyBits;
	return dh;

failed:
	if(dh)
		DH_free(dh);

	return 0;
}

int DHGenerateKey(DH *dh)
{
	if(!dh)
		return 0;

	int res = 0;
	while(!res)
	{
		if(!DH_generate_key(dh))
			return 0;
	
		BIGNUM *q1 = BN_new();
		assert(BN_hex2bn(&q1, Q1024));

		res = isValidPublicKey(dh->pub_key, dh->p, q1);
		if(!res) {
			BN_free(dh->pub_key);
			BN_free(dh->priv_key);
			dh->pub_key = dh->priv_key = 0;
		}

		BN_free(q1);
	}
	return 1;
}

// fill pubkey with the public key in BIG ENDIAN order
// 00 00 00 00 00 x1 x2 x3 .....

int DHGetPublicKey(DH *dh, uint8_t *pubkey, size_t nPubkeyLen)
{
	if(!dh || !dh->pub_key)
		return 0;
	
	int len = BN_num_bytes(dh->pub_key);
	if(len <= 0 || len > (int)nPubkeyLen)
		return 0;

	memset(pubkey, 0, nPubkeyLen);
	BN_bn2bin(dh->pub_key, pubkey + (nPubkeyLen - len));
	return 1;
}

int DHGetPrivateKey(DH *dh, uint8_t *privkey, size_t nPrivkeyLen)
{
        if(!dh || !dh->priv_key)
                return 0;
        
        int len = BN_num_bytes(dh->priv_key);
        if(len <= 0 || len > (int)nPrivkeyLen)
                return 0;

        memset(privkey, 0, nPrivkeyLen);
        BN_bn2bin(dh->priv_key, privkey + (nPrivkeyLen - len));
        return 1;
}

// computes the shared secret key from the private DH value and the othe parties public key (pubkey)
int DHComputeSharedSecretKey(DH *dh, uint8_t *pubkey, size_t nPubkeyLen, uint8_t *secret)
{
	if(!dh || !secret || nPubkeyLen >= INT_MAX)
		return -1;

	BIGNUM *pubkeyBn = BN_bin2bn(pubkey, nPubkeyLen, 0);
	if(!pubkeyBn)
		return -1;

	BIGNUM *q1 = BN_new();
        assert(BN_hex2bn(&q1, Q1024));
	
	if(!isValidPublicKey(pubkeyBn, dh->p, q1)) {
		BN_free(pubkeyBn);
		BN_free(q1);
		return -1;
	}

	BN_free(q1);

	size_t len = DH_compute_key(secret, pubkeyBn, dh);
	BN_free(pubkeyBn);

	return len;
}

void DHFree(DH *dh)
{
	if(dh)
		DH_free(dh);
}

