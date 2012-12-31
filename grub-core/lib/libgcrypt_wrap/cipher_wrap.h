/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2009  Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef GRUB_GCRY_WRAP_HEADER
#define GRUB_GCRY_WRAP_HEADER 1

#include <grub/types.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/dl.h>
#include <grub/crypto.h>

#undef WORDS_BIGENDIAN

#ifdef GRUB_CPU_WORDS_BIGENDIAN
#define WORDS_BIGENDIAN 1
#endif

#undef __GNU_LIBRARY__
#define __GNU_LIBRARY__ 1

#define DIM ARRAY_SIZE

typedef grub_uint64_t u64;
typedef grub_uint32_t u32;
typedef grub_uint16_t u16;
typedef grub_uint8_t byte;
typedef grub_size_t size_t;

#define U64_C(c) (c ## ULL)

#define _gcry_burn_stack grub_burn_stack
#define log_error(fmt, args...) grub_dprintf ("crypto", fmt, ## args)


#define PUBKEY_FLAG_NO_BLINDING    (1 << 0)

#define CIPHER_INFO_NO_WEAK_KEY    1

#define HAVE_U64_TYPEDEF 1

typedef union {
    int a;
    short b;
    char c[1];
    long d;
#ifdef HAVE_U64_TYPEDEF
    u64 e;
#endif
    float f;
    double g;
} PROPERLY_ALIGNED_TYPE;

#define gcry_assert(x) grub_assert_real(GRUB_FILE, __LINE__, x)

static inline void
grub_assert_real (const char *file, int line, int cond)
{
  if (!cond)
    grub_fatal ("Assertion failed at %s:%d\n", file, line);
}

/* Selftests are in separate modules.  */
static inline char *
selftest (void)
{
  return NULL;
}

static inline int
fips_mode (void)
{
  return 0;
}

#ifdef GRUB_UTIL
#pragma GCC diagnostic ignored "-Wshadow"
static inline void *
memcpy (void *dest, const void *src, grub_size_t n)
{
  return grub_memcpy (dest, src, n);
}

static inline void *
memset (void *s, int c, grub_size_t n)
{
  return grub_memset (s, c, n);
}

static inline int
memcmp (const void *s1, const void *s2, grub_size_t n)
{
  return grub_memcmp (s1, s2, n);
}
#pragma GCC diagnostic error "-Wshadow"
#endif

/* Following stuff is taken from libgcrypt headers: */

/* src/cipher.h */
#define DBG_CIPHER 0

extern gcry_md_spec_t _gcry_digest_spec_crc32;
extern gcry_md_spec_t _gcry_digest_spec_crc32_rfc1510;
extern gcry_md_spec_t _gcry_digest_spec_crc24_rfc2440;
extern gcry_md_spec_t _gcry_digest_spec_md4;
extern gcry_md_spec_t _gcry_digest_spec_md5;
extern gcry_md_spec_t _gcry_digest_spec_rmd160;
extern gcry_md_spec_t _gcry_digest_spec_sha1;
extern gcry_md_spec_t _gcry_digest_spec_sha224;
extern gcry_md_spec_t _gcry_digest_spec_sha256;
extern gcry_md_spec_t _gcry_digest_spec_sha512;
extern gcry_md_spec_t _gcry_digest_spec_sha384;
extern gcry_md_spec_t _gcry_digest_spec_tiger;
extern gcry_md_spec_t _gcry_digest_spec_tiger1;
extern gcry_md_spec_t _gcry_digest_spec_tiger2;
extern gcry_md_spec_t _gcry_digest_spec_whirlpool;


/* src/gcrypt.h */
typedef enum gcry_random_level
  {
    GCRY_WEAK_RANDOM = 0,
    GCRY_STRONG_RANDOM = 1,
    GCRY_VERY_STRONG_RANDOM = 2
  }
gcry_random_level_t;

struct gcry_sexp;
typedef struct gcry_sexp *gcry_sexp_t;

enum gcry_mpi_format
  {
    GCRYMPI_FMT_NONE= 0,
    GCRYMPI_FMT_STD = 1,    /* Twos complement stored without length.  */
    GCRYMPI_FMT_PGP = 2,    /* As used by OpenPGP (unsigned only).  */
    GCRYMPI_FMT_SSH = 3,    /* As used by SSH (like STD but with length).  */
    GCRYMPI_FMT_HEX = 4,    /* Hex format. */
    GCRYMPI_FMT_USG = 5     /* Like STD but unsigned. */
  };


/* Flags describing usage capabilities of a PK algorithm. */
#define GCRY_PK_USAGE_SIGN 1   /* Good for signatures. */
#define GCRY_PK_USAGE_ENCR 2   /* Good for encryption. */
#define GCRY_PK_USAGE_CERT 4   /* Good to certify other keys. */
#define GCRY_PK_USAGE_AUTH 8   /* Good for authentication. */
#define GCRY_PK_USAGE_UNKN 128 /* Unknown usage flag. */

typedef struct gcry_md_handle
{
  /* Actual context.  */
  struct gcry_md_context *ctx;

  /* Buffer management.  */
  int  bufpos;
  int  bufsize;
  unsigned char buf[1];
} *gcry_md_hd_t;


/* src/mpi.h */
/* Context used with elliptic curve functions.  */
struct mpi_ec_ctx_s;
typedef struct mpi_ec_ctx_s *mpi_ec_t;

#define BYTES_PER_MPI_LIMB  (sizeof(unsigned long)) // XXX
#define BITS_PER_MPI_LIMB    (8*BYTES_PER_MPI_LIMB)

#define MPI_NULL NULL

#endif
