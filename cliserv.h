#ifndef NBD_CLISERV_H
#define NBD_CLISERV_H 1

/* This header file is shared by client & server. They really have
 * something to share...
 * */

/* Client/server protocol is as follows:
   Password authentication if specified
   Send NBD_HELLO
   Send 64-bit cliserv_magic
   Send 64-bit size of exported device
   Send 128 bytes of zeros (reserved for future use)
 */

#include "config.h"

#include "lfs.h"

#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <stdlib.h>

#if SIZEOF_UNSIGNED_SHORT_INT==4
typedef unsigned short u32;
#elif SIZEOF_UNSIGNED_INT==4
typedef unsigned int u32;
#elif SIZEOF_UNSIGNED_LONG_INT==4
typedef unsigned long u32;
#else
#error I need at least some 32-bit type
#endif

#if SIZEOF_UNSIGNED_INT==8
typedef unsigned int u64;
#elif SIZEOF_UNSIGNED_LONG_INT==8
typedef unsigned long u64;
#elif SIZEOF_UNSIGNED_LONG_LONG_INT==8
typedef unsigned long long u64;
#else
#error I need at least some 64-bit type
#endif

#define __be32 u32
#define __be64 u64
#include "nbd.h"

#if NBD_LFS==1
#define _LARGEFILE_SOURCE
#define _FILE_OFFSET_BITS 64
#endif

#define cliserv_magic 0x00420281861253LL
#define NBD_HELLO "NBDMAGIC"

#define INFO(a) do { } while(0)

void setmysockopt(int sock);
#ifndef G_GNUC_NORETURN
#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ > 4)
#define G_GNUC_NORETURN __attribute__((__noreturn__))
#else
#define G_GNUC_NORETURN
#endif
#endif

void err(const char *s) G_GNUC_NORETURN;

#endif /* NBD_AUTH_C */
u64 ntohll(u64 a);
#define htonll ntohll

/* Flags used between the client and server */
#define NBD_FLAG_HAS_FLAGS	(1 << 0)	/* Flags are there */
#define NBD_FLAG_READ_ONLY	(1 << 1)	/* Device is read-only */

#endif /* NBD_CLISERV_H */
