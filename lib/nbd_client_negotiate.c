#include "config.h"
#include <unistd.h>
#include "libnbd.h"

int nbd_client_negotiate(int sock, u64 *rsize64, u32 *flags, char* name) {
	u64 magic, size64;
	uint16_t tmp;
	char buf[256] = "\0\0\0\0\0\0\0\0\0";

	if (read(sock, buf, 8) < 0)
		return -errno;
	if (strlen(buf)==0)
		return -EIO;
	if (strcmp(buf, INIT_PASSWD))
		return -EINVAL;
	if (read(sock, &magic, sizeof(magic)) < 0)
		return -EINVAL;
	magic = ntohll(magic);
	if(name) {
		uint32_t opt;
		uint32_t namesize;
		uint32_t reserved = 0;

		if (magic != opts_magic)
			return -EIO;
		if(read(sock, &tmp, sizeof(uint16_t)) < 0) {
			return -errno;
		}
		*flags = ((u32)ntohs(tmp)) << 16;

		/* reserved for future use*/
		if (write(sock, &reserved, sizeof(reserved)) < 0)
			return -errno;

		/* Write the export name that we're after */
		magic = ntohll(opts_magic);
		if (write(sock, &magic, sizeof(magic)) < 0)
			return -errno;
		opt = ntohl(NBD_OPT_EXPORT_NAME);
		if (write(sock, &opt, sizeof(opt)) < 0)
			return -errno;
		namesize = (u32)strlen(name);
		namesize = ntohl(namesize);
		if (write(sock, &namesize, sizeof(namesize)) < 0)
			return -errno;
		if (write(sock, name, strlen(name)) < 0)
			return -errno;
	} else {
		if (magic != cliserv_magic)
			return -EINVAL;
	}

	if (read(sock, &size64, sizeof(size64)) < 0)
		return -errno;
	size64 = ntohll(size64);

#ifdef NBD_SET_SIZE_BLOCKS
	if ((size64>>10) > (~0UL >> 1)) {
		return -EFBIG;
	}
#else
	if (size64 > (~0UL >> 1)) {
		return -EFBIG;
	}
#endif

	if(!name) {
		if (read(sock, flags, sizeof(*flags)) < 0)
			return -errno;
		*flags = ntohl(*flags);
	} else {
		if(read(sock, &tmp, sizeof(tmp)) < 0)
			return -errno;
		*flags |= (uint32_t)ntohs(tmp);
	}

	if (read(sock, &buf, 124) < 0)
		return -errno;

	*rsize64 = size64;

	return 0;
}
