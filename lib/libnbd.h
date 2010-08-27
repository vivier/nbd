/* This header file is shared by client & server. They really have
 * something to share...
 * */

/* Client/server protocol is as follows:
   Send INIT_PASSWD
   Send 64-bit cliserv_magic
   Send 64-bit size of exported device
   Send 128 bytes of zeros (reserved for future use)
 */

#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <glib.h>

#if HAVE_LINUX_TYPES_H
#include <linux/types.h>
#else
#define __be32 u32
#define __be64 u64
#endif

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


#include "nbd.h"

#if NBD_LFS==1
#define _LARGEFILE_SOURCE
#define _FILE_OFFSET_BITS 64
#endif

#define cliserv_magic 0x00420281861253LL
#define opts_magic 0x49484156454F5054LL
#define INIT_PASSWD "NBDMAGIC"

#define INFO(a) do { } while(0)

#ifdef WORDS_BIGENDIAN
static inline u64 ntohll(u64 a) {
	return a;
}
#else
static inline u64 ntohll(u64 a) {
	u32 lo = a & 0xffffffff;
	u32 hi = a >> 32U;
	lo = ntohl(lo);
	hi = ntohl(hi);
	return ((u64) lo) << 32U | hi;
}
#endif
#define htonll ntohll

/* Flags used between the client and server */
#define NBD_FLAG_HAS_FLAGS	(1 << 0)	/* Flags are there */
#define NBD_FLAG_READ_ONLY	(1 << 1)	/* Device is read-only */

#define NBD_DEFAULT_PORT	"10809"	/* Port on which named exports are
					 * served */

/* Options that the client can select to the server */
#define NBD_OPT_EXPORT_NAME	(1 << 0)	/* Client wants to select a named export (is followed by length and name of export) */

/**
 * The highest value a variable of type off_t can reach. This is a signed
 * integer, so set all bits except for the leftmost one.
 **/
#define OFFT_MAX ~((off_t)1<<(sizeof(off_t)*8-1))
#define LINELEN 256	  /**< Size of static buffer used to read the
			       authorization file (yuck) */
#define BUFSIZE (1024*1024) /**< Size of buffer that can hold requests */
#define DIFFPAGESIZE 4096 /**< diff file uses those chunks */
#define F_READONLY 1      /**< flag to tell us a file is readonly */
#define F_MULTIFILE 2	  /**< flag to tell us a file is exported using -m */
#define F_COPYONWRITE 4	  /**< flag to tell us a file is exported using
			    copyonwrite */
#define F_AUTOREADONLY 8  /**< flag to tell us a file is set to autoreadonly */
#define F_SPARSE 16	  /**< flag to tell us copyronwrite should use a sparse file */
#define F_SDP 32	  /**< flag to tell us the export should be done using the Socket Direct Protocol for RDMA */
#define F_SYNC 64	  /**< Whether to fsync() after a write */
/**
 * Types of virtuatlization
 **/
typedef enum {
	VIRT_NONE=0,	/**< No virtualization */
	VIRT_IPLIT,	/**< Literal IP address as part of the filename */
	VIRT_IPHASH,	/**< Replacing all dots in an ip address by a / before
			     doing the same as in IPLIT */
	VIRT_CIDR,	/**< Every subnet in its own directory */
} VIRT_STYLE;

/**
 * Variables associated with a server.
 **/
typedef struct {
	gchar* exportname;    /**< (unprocessed) filename of the file we're exporting */
	off_t expected_size; /**< size of the exported file as it was told to
			       us through configuration */
	gchar* listenaddr;   /**< The IP address we're listening on */
	unsigned int port;   /**< port we're exporting this file at */
	char* authname;      /**< filename of the authorization file */
	int flags;           /**< flags associated with this exported file */
	int socket;	     /**< The socket of this server. */
	int socket_family;   /**< family of the socket */
	VIRT_STYLE virtstyle;/**< The style of virtualization, if any */
	uint8_t cidrlen;     /**< The length of the mask when we use
				  CIDR-style virtualization */
	gchar* prerun;	     /**< command to be ran after connecting a client,
				  but before starting to serve */
	gchar* postrun;	     /**< command that will be ran after the client
				  disconnects */
	gchar* servename;    /**< name of the export as selected by nbd-client */
} SERVER;
typedef struct {
	off_t exportsize;    /**< size of the file we're exporting */
	char *clientname;    /**< peer */
	char *exportname;    /**< (processed) filename of the file we're exporting */
	GArray *export;    /**< array of FILE_INFO of exported files;
			       array size is always 1 unless we're
			       doing the multiple file option */
	int net;	     /**< The actual client socket */
	SERVER *server;	     /**< The server this client is getting data from */
	char* difffilename;  /**< filename of the copy-on-write file, if any */
	int difffile;	     /**< filedescriptor of copyonwrite file. @todo
			       shouldn't this be an array too? (cfr export) Or
			       make -m and -c mutually exclusive */
	u32 difffilelen;     /**< number of pages in difffile */
	u32 *difmap;	     /**< see comment on the global difmap for this one */
	gboolean modern;     /**< client was negotiated using modern negotiation protocol */
} CLIENT;

extern char *nbd_server_negotiate_new_style(int net);
extern int nbd_server_negotiate_info_new_style(int net, uint64_t size,
					       uint32_t flags);
extern int nbd_server_negotiate_old_style(int net);
extern int nbd_server_negotiate_info_old_style(int net, uint64_t size,
					       uint32_t flags);
extern int nbd_server_loop(CLIENT *client, char *buf, int len);

extern int expwrite(off_t a, char *buf, size_t len, CLIENT *client);
extern int expread(off_t a, char *buf, size_t len, CLIENT *client);

extern int nbd_client_set_timeout(int nbd, int timeout);
extern int nbd_client_setsizes(int nbd, u64 size64, int blocksize, u32 flags);
extern int nbd_client_negotiate(int sock, u64 *rsize64, u32 *flags, char* name);
extern int nbd_client_finish_sock(int sock, int nbd, int swap);
extern int nbd_client_disconnect(char* device);
extern int nbd_client_do(int nbd);
extern int nbd_client_clear(int nbd);
