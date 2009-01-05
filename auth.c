#include <sys/socket.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <config.h>
#define NBD_AUTH_C 1	/* for cliserv.h */
#include <cliserv.h>
#include <auth.h>
#include <sha2.h>
#include <unistd.h>

#ifdef NBD_AUTH

/* Debugging macros */
#ifdef DODBG
#define DEBUG( a ) fprintf(stderr, a )
#define DEBUG2( a,b ) fprintf(stderr, a,b )
#define DEBUG3( a,b,c ) fprintf(stderr, a,b,c )
#define DEBUG4( a,b,c,d ) fprintf(stderr, a,b,c,d )
void debug_hexdump(char *name, unsigned char *x,size_t len) {
	size_t i;
	for (i=0;i<len;++i) {
		fprintf(stderr, "%02X%c", x[i], isprint(x[i])?x[i]:'_');
	}
	fprintf(stderr, " %s\n",name);
}
#else /* DODBG */
#define DEBUG( a )
#define DEBUG2( a,b ) 
#define DEBUG3( a,b,c ) 
#define DEBUG4( a,b,c,d ) 
#define debug_hexdump(x)
#endif /* DODBG */

#ifndef PACKAGE_VERSION
#define PACKAGE_VERSION ""
#endif

#define HOSTNUMS_SPACESZ ((NI_MAXHOST+NI_MAXSERV*2)*2) /* socknums arg to socktonumbrs */

#ifndef NI_MAXHOST
#define NI_MAXHOST      1025
#endif
#ifndef NI_MAXSERV
#define NI_MAXSERV      32
#endif

/* I first implemented this with getnameinfo(), but since CYGWIN
   doesn't have that at all, I went back and used my preferred format,
   binary network byte order (NBO), after I finally 1learned enough to
   find all the include files and names to get at it; here's all I
   need to know: */

#include <netinet/in.h>
#include <arpa/inet.h>

/*
struct  in_addr sin_addr;	/ *  32 bit IPv4 address, NBO * /
struct in6_addr sin6_addr;	/ * 128 bit IPv6 address, NBO * /

/ * Structure describing an Internet socket address.  * /
struct sockaddr_in {
    __SOCKADDR_COMMON (sin_);
    in_port_t sin_port;                 / * Port number.  * /
    struct in_addr sin_addr;            / * Internet address.  * /

    / * Pad to size of `struct sockaddr'.  * /
    unsigned char sin_zero[sizeof (struct sockaddr) -
                           __SOCKADDR_COMMON_SIZE -
                           sizeof (in_port_t) -
                           sizeof (struct in_addr)];
  };

/ * Ditto, for IPv6.  * /
struct sockaddr_in6 {
    __SOCKADDR_COMMON (sin6_);
    in_port_t sin6_port;        / * Transport layer port # * /
    uint32_t sin6_flowinfo;     / * IPv6 flow information * /
    struct in6_addr sin6_addr;  / * IPv6 address * /
    uint32_t sin6_scope_id;     / * IPv6 scope-id * /
  };
*/

/* standardize sockaddr formats for us; needs to be portably canonical */
/* default to default, otherwise map for known families for portability */
#define	NBD_AF_INET	(2)
#define	NBD_AF_INET6	(10)
#ifdef AF_INET6
#define FamilyCanon(x)	(((x)==AF_INET)?NBD_AF_INET:(((x)==AF_INET6)? \
				NBD_AF_INET6:(x)))
#define Addr6(y)	(((struct sockaddr_in6*)y)->sin6_addr)
#define Port6(y)	(((struct sockaddr_in6*)y)->sin6_port)
#else /* AF_INET6 */
#define FamilyCanon(x)	(((x)==AF_INET)?NBD_AF_INET:(x))
#endif /* AF_INET6 */
#define Family(y)	(((struct sockaddr*)y)->sa_family)
#define Addr4(y)	(((struct sockaddr_in*)y)->sin_addr)
#define Port4(y)	(((struct sockaddr_in*)y)->sin_port)

static void socktonum(struct sockaddr_storage *sastg, socklen_t sastg_len, unsigned char *dat, size_t *pos) {
	/* typedef unsigned short uint16_t; / * comment out if already defined */
	uint16_t family;

	/* Must include Family, IP#, AND PORT for proper security. */

	family=htons(FamilyCanon(Family(sastg)));
	memcpy(dat+*pos,(void*)&family,sizeof(family));
	(*pos)+=sizeof(family);

	switch(Family(sastg)) {
	    case AF_INET:
		memcpy(dat+*pos,(void*)&(Addr4(sastg)),	sizeof(Addr4(sastg)));
		(*pos)+=				sizeof(Addr4(sastg));
		memcpy(dat+*pos,(void*)&(Port4(sastg)),	sizeof(Port4(sastg)));
		(*pos)+=				sizeof(Port4(sastg));
		break;
#ifdef AF_INET6
	    case AF_INET6:
		memcpy(dat+*pos,(void*)&(Addr6(sastg)),	sizeof(Addr6(sastg)));
		(*pos)+=				sizeof(Addr6(sastg));
		memcpy(dat+*pos,(void*)&(Port6(sastg)),	sizeof(Port6(sastg)));
		(*pos)+=				sizeof(Port6(sastg));
		break;
#endif /* AF_INET6 */
	    default:
		fprintf(stderr, "Unimplemented family %u; trying binary data \
(probably will not work);\nEnhance auth.c socktonum() to handle your family \
& submit patch.\n", Family(sastg));
		memcpy( dat+*pos,(void*)sastg,	sastg_len);
		Family((dat+*pos))=family;
		(*pos)+=			sastg_len;
		break;
	}
}

/* given socket and a buffer socknums of size HOSTNUMS_SPACESZ, returns
   length of buffer used for canonical identity information including
   family, address, and port */
static size_t socktonumbers(int sock,unsigned char *socknums,who_am_i who) {
	struct sockaddr_storage sastg;
	socklen_t sastg_len=sizeof(sastg);
	size_t pos=0; /* must be zero */

#define GetSocketInfo(getfunc) { \
		if (getfunc(sock, (struct sockaddr*)&sastg, &sastg_len) < 0) \
			err("getsockname/getpeername %m"); \
	}
	if(who==NBD_WHO_SERVER)	GetSocketInfo(getsockname)
	else			GetSocketInfo(getpeername)
	socktonum(&sastg,sastg_len,socknums,&pos);

	if(who==NBD_WHO_SERVER)	GetSocketInfo(getpeername)
	else			GetSocketInfo(getsockname)
	socktonum(&sastg,sastg_len,socknums,&pos);

#undef GetSocketInfo
	return pos;
}

static void nbd_authhash(uint8_t *digest, unsigned char *hashdat, size_t hashlen, char *pass, size_t passlen) {
	SHA512_CTX hashcontext;

	SHA512_Init(&hashcontext);
	SHA512_Update(&hashcontext, hashdat, hashlen);
	SHA512_Update(&hashcontext, (unsigned char*)pass, passlen);
	SHA512_Final(digest,&hashcontext);
}

void nbd_auth(int sock, char *clientpass, who_am_i who) {
	int f;
	int r;
	int i;
	uint8_t mydigest[SHA512_DIGEST_LENGTH];
	uint8_t	theirdigest[SHA512_DIGEST_LENGTH];
	char *rand;
	char *serverpass=clientpass;
	size_t clientpasslen;
	size_t serverpasslen;
	size_t commonhashlen;
	unsigned char hashdat[NBD_AUTHSZ+HOSTNUMS_SPACESZ];

	/* hash in order:  random, identity, password */
	commonhashlen=NBD_AUTHSZ+socktonumbers(sock,hashdat+NBD_AUTHSZ,who);

	serverpasslen=clientpasslen=strlen(clientpass);
	if(seppass) {		/* be sure to use a very big clientpass */
		serverpasslen -= (clientpasslen /= 2);
		serverpass    +=  clientpasslen;
	}

	DEBUG2("Debug password(s):  \"%s\"\n", clientpass);
	DEBUG4("%ssing separate passwords: clientpasslen %u, serverpasslen %u\n",
		(seppass?"U":"Not u"), clientpasslen, serverpasslen);

	if(who==NBD_WHO_CLIENT) goto getrandom;

sendrandom:
	/* Send random to other, both apply server & client families &
	ips & ports & password, both digest, get back from other and
	compare. */

	if(morerandom)	{
		rand="/dev/random";	/* Flag for strong random */
		fprintf(stderr,
			"Reading from %s; this can take a while", rand);
	} else	rand="/dev/urandom";
	if((f=open(rand,O_RDONLY))==-1) { err("open rand: %m"); exit(54); }
	i=0; readloop:
	r=read(f,hashdat+i,NBD_AUTHSZ-i);
	if(r==-1) { err("read rand: %m"); exit(55); }
	i+=r;
	if(i<NBD_AUTHSZ) {
		fprintf(stderr, ".");
		goto readloop;
	}
	if(close(f)==-1) err("close rand: %m");
	if(morerandom) fprintf(stderr, " Done.\n");

	if (write(sock, hashdat, (size_t)NBD_AUTHSZ) < 0) {
		if(who==NBD_WHO_SERVER) {
			err("auth write send: %m");
		} else {
			err("auth write send: %m; Check if nbd-server doesn't have passwords.");
		}
	}

	nbd_authhash(mydigest, hashdat, commonhashlen,
	    (who==NBD_WHO_SERVER)?clientpass:serverpass,
	    (who==NBD_WHO_SERVER)?clientpasslen:serverpasslen);

	if(read(sock, (unsigned char*)theirdigest,
	    (size_t)SHA512_DIGEST_LENGTH)!=SHA512_DIGEST_LENGTH) {
		if (who==NBD_WHO_SERVER) {
			err("Auth read back: %m\n\
Check if nbd-client failed to set its passwords right.");
		} else {
			err("Auth read back: %m\n\
Check your passwords and make sure they are the same here & nbd-server");
		}
	}
	if(memcmp(mydigest,theirdigest,(size_t)SHA512_DIGEST_LENGTH)) {
		err("Bad password!");
		exit(59);			/* just to be sure */
	}
	if(who==NBD_WHO_CLIENT) {
		printf("server password ok");
		goto end;
	}

getrandom:
	/* Get random from other, both apply server & client families
	& ips & ports & password, both digest, send back to other for
	them to compare. */

	if (read(sock, hashdat, (size_t)NBD_AUTHSZ) < 0)
		err("Auth read get: %m");

	nbd_authhash(mydigest, hashdat, commonhashlen,
		(who==NBD_WHO_CLIENT)?clientpass:serverpass,
		(who==NBD_WHO_CLIENT)?clientpasslen:serverpasslen);

	if(write(sock, (unsigned char*)mydigest, (size_t)SHA512_DIGEST_LENGTH)
	   !=SHA512_DIGEST_LENGTH) err("Auth write back: %m");
	if(who==NBD_WHO_CLIENT) goto sendrandom;

	end:
	return;
}

#endif /* NBD_AUTH */
