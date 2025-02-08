/*
    ChibiOS - Copyright (C) 2006..2018 Giovanni Di Sirio
    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at
        http://www.apache.org/licenses/LICENSE-2.0
    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/
/*
 * **** This file incorporates work covered by the following copyright and ****
 * **** permission notice:                                                 ****
 *
 * Copyright (C) 2006-2017 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */


#ifndef WOLFSSL_HELPERS_H
#define WOLFSSL_HELPERS_H

#include "hwdef.h"
// #include "stdio.h"

// /* HW RNG support */
// ///@brief make sure we use our strerror_r function
#define HAVE_PK_CALLBACKS
#define WOLFSSL_USER_IO
#define NO_WRITEV
// #define XMALLOC_OVERRIDE
#define NO_CRYPT_BENCHMARK
#define NO_CRYPT_TEST
#define WOLFCRYPT_ONLY
#define NO_HMAC
#define NO_MD5
#define NO_OLD_TLS

#ifdef HAL_BOOTLOADER_BUILD
#define NO_ERROR_STRINGS
#define WOLFSSL_SMALL_STACK
#endif

#define NO_AES_CBC 
#define NO_WOLFSSL_SERVER

// #define CUSTOM_RAND_GENERATE wolfssl_rand_get
// #define CUSTOM_RAND_TYPE uint32_t

#define NO_STM32_CRYPTO
#define NO_STM32_RNG


/* Realloc (to use without USE_FAST_MATH) */

// #define XREALLOC(p,n,h,t) ((void*)std_realloc( (p) , (n) )); (void)h; (void)t
// #define XMALLOC(s,h,t) ((void*)malloc(s)); (void)h; (void)t
// #define XFREE(p,h,t)   free(p)



// #include <stdint.h>

// /* Configuration */

#define WOLFSSL_GENERAL_ALIGNMENT 4
#define HAVE_TM_TYPE
#define WORD64_AVAILABLE


// /* ARM  */	
#define RSA_LOW_MEM
// #define NO_OLD_RNGNAME  
#define SMALL_SESSION_CACHE
#define WOLFSSL_SMALL_STACK

// #define TFM_ARM
// // #define SINGLE_THREADED
// #define NO_SIG_WRAPPER
		
// /* Cipher features */
// #define USE_FAST_MATH
// //#define ALT_ECC_SIZE

// // #define HAVE_FFDHE_2048
// // #define HAVE_CHACHA 
// // #define HAVE_POLY1305 
// // #define HAVE_ECC 
// #define HAVE_CURVE25519
// #define CURVED25519_SMALL
// #define HAVE_ONE_TIME_AUTH
// #define WOLFSSL_DH_CONST
		
// HW RNG support 
unsigned int chibios_rand_generate(void);
int custom_rand_generate_block(unsigned char* output, unsigned int sz);

#define CUSTOM_RAND_GENERATE chibios_rand_generate
#define CUSTOM_RAND_TYPE uint32_t

// #define HAVE_ED25519
// // #define HAVE_POLY1305
// #define HAVE_SHA512
// #define WOLFSSL_SHA512


// /* Size/speed config */
// #define USE_SLOW_SHA2
// #define USE_SLOW_SHA512

/* Robustness */
// #define TFM_TIMING_RESISTANT
// #define ECC_TIMING_RESISTANT
// #define WC_RSA_BLINDING

// /* Remove Features */
// #define NO_WRITEV
// #define NO_DEV_RANDOM
// // #define NO_FILESYSTEM
// #define NO_MAIN_DRIVER
// // #define NO_MD4
// #define NO_RABBIT
// #define NO_HC128
// // #define NO_DSA
// #define NO_PWDBASED
// // #define NO_PSK
// // #define NO_DES3
// // #define NO_RC4

#endif
