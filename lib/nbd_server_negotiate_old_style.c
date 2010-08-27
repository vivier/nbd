#include "config.h"

#include <stdint.h>
#include <unistd.h>
#include "libnbd.h"

int nbd_server_negotiate_old_style(int net)
{
	uint32_t magic;

	/* passwd[8]	INIT_PASSWD	"NBDMAGIC"
	 * magic[8]	cliserv_magic	0x00420281861253LL
	 */

	if (write(net, INIT_PASSWD, strlen(INIT_PASSWD)) !=
	    strlen(INIT_PASSWD)) {
		return -errno;
	}

	magic = htonll(cliserv_magic);

	if (write(net, &magic, sizeof(magic)) != sizeof(magic)) {
		return -errno;
	}

	return 0;
}

int nbd_server_negotiate_info_old_style(int net, uint64_t size, uint32_t flags)
{
	char zeros[128];

	memset(zeros, '\0', sizeof(zeros));

	size = htonll(size);
	if (write(net, &size, sizeof(size)) < sizeof(size)) {
		return -errno;
	}

	flags = htonl(flags);
	if (write(net, &flags, sizeof(flags)) != sizeof(flags)) {
		return -errno;
	}

	if (write(net, zeros, 124) != 124) {
		return -errno;
	}

	return 0;
}
