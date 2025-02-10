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

#define WOLF_CONF_WOLFCRYPT_ONLY      0
#define WOLFCRYPT_ONLY

// /* HW RNG support */
// ///@brief make sure we use our strerror_r function
#define NO_WRITEV
// #define XMALLOC_OVERRIDE
#define NO_CRYPT_BENCHMARK
#define NO_CRYPT_TEST
#define NO_HMAC
#define NO_MD5
#define NO_OLD_TLS

#define NO_CHACHA
#define NO_POLY1305 
#define NO_ECC


#ifdef HAL_BOOTLOADER_BUILD
#define NO_ERROR_STRINGS
// #define NO_RSA
#define WOLFSSL_SMALL_STACK
#else
#define SHOW_GEN
#endif

#define NO_AES_CBC 
#define NO_WOLFSSL_SERVER

// #define CUSTOM_RAND_GENERATE wolfssl_rand_get
// #define CUSTOM_RAND_TYPE uint32_t

#define NO_STM32_CRYPTO
#define NO_STM32_RNG
#define NO_STM32_HASH

// CubeOrange
// env added APJ_BOARD_TYPE=STM32H743xx
// #define WOLFSSL_STM32H7
//#define HAL_CONSOLE_UART huart3

#define SIZEOF_LONG_LONG 8
#define WOLFSSL_GENERAL_ALIGNMENT 4
// #define WOLFSSL_STM32_CUBEMX
// #define WOLFSSL_SMALL_STACK
#define WOLFSSL_NO_SOCK
#define WOLFSSL_IGNORE_FILE_WARN
#define HAVE_PK_CALLBACKS
#define WOLFSSL_USER_IO

/* single precision only */
#define WOLFSSL_SP
#define WOLFSSL_SP_SMALL      /* use smaller version of code */
#define WOLFSSL_HAVE_SP_RSA
#define WOLFSSL_HAVE_SP_DH
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_SP_MATH
#define SP_WORD_SIZE 32

//#define WOLFSSL_SP_NO_MALLOC
//#define WOLFSSL_SP_CACHE_RESISTANT

/* single precision Cortex-M only */
#define WOLFSSL_SP_ASM /* required if using the ASM versions */
#define WOLFSSL_SP_ARM_CORTEX_M_ASM


// Fix error with uint64_t does not define a type
#define ULONG_MAX 18446744073709551615ULL
// 0xffffffffUL
#define ULLONG_MAX 18446744073709551615ULL


/* Realloc (to use without USE_FAST_MATH) */

// #define XREALLOC(p,n,h,t) ((void*)std_realloc( (p) , (n) )); (void)h; (void)t
// #define XMALLOC(s,h,t) ((void*)malloc(s)); (void)h; (void)t
// #define XFREE(p,h,t)   free(p)



// #include <stdint.h>

// /* Configuration */

#define HAVE_TM_TYPE
// #define WORD64_AVAILABLE


// /* ARM  */	
// `RSA_LOW_MEM`: Half as much memory but twice as slow. Uses Non-CRT method for private key.
// #define RSA_LOW_MEM
// #define NO_OLD_RNGNAME  
// #define SMALL_SESSION_CACHE
// #define WOLFSSL_SMALL_STACK

// #define TFM_ARM
// // #define SINGLE_THREADED
// #define NO_SIG_WRAPPER
		
// /* Cipher features */
/* 
USE_FAST_MATH: Uses stack based math, which is faster than the heap based math.
ALT_ECC_SIZE: If using fast math and RSA/DH you can define this to reduce your ECC memory consumption.
FP_MAX_BITS: Is the maximum math size (key size * 2). Used only with `USE_FAST_MATH`.
*/
#define USE_FAST_MATH
#define ALT_ECC_SIZE
#define FP_MAX_BITS     4096

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
