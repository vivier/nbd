#include "config.h"

#include <stdint.h>
#include <unistd.h>
#include "libnbd.h"

static int new_style_header(int net)
{
	uint32_t magic;

	/* passwd[8]	INIT_PASSWD	"NBDMAGIC"
	 * magic[8]	opts_magic	0x49484156454F5054LL
	 */

	if (write(net, INIT_PASSWD, strlen(INIT_PASSWD)) !=
	    strlen(INIT_PASSWD)) {
		return -errno;
	}

	magic = htonll(opts_magic);

	if (write(net, &magic, sizeof(magic)) != sizeof(magic)) {
		return -errno;
	}
	return 0;
}

static char *negotiate_name(int net)
{
	/* server		client
	 *
	 * smallflags[2]   ->
	 *		   <-	reserverd[4]
	 *		   <-	magic[8]	0x49484156454F5054LL
	 *		   <-	opt[4]		NBD_OPT_EXPORT_NAME
	 *		   <-	namelen[4]	srlen(name)
	 *		   <-	name[namelen]	"....."
	 */

	uint16_t smallflags = 0;
	uint32_t reserved;
	uint64_t magic;
	uint32_t opt;
	uint32_t namelen;
	char* name;

	if (write(net, &smallflags, sizeof(uint16_t)) < 0) {
		return NULL;
	}
	if (read(net, &reserved, sizeof(reserved)) < 0) {
		return NULL;
	}
	if (read(net, &magic, sizeof(magic)) < 0) {
		return NULL;
	}
	magic = ntohll(magic);
	if(magic != opts_magic) {
		return NULL;
	}
	if (read(net, &opt, sizeof(opt)) < 0) {
		return NULL;
	}
	opt = ntohl(opt);
	if(opt != NBD_OPT_EXPORT_NAME) {
		return NULL;
	}
	if (read(net, &namelen, sizeof(namelen)) < 0) {
		return NULL;
	}

	namelen = ntohl(namelen);
	name = malloc(namelen+1);
	name[namelen] = 0;
	if (read(net, name, namelen) < 0) {
		return NULL;
	}
	return name;
}

char *nbd_server_negotiate_new_style(int net)
{
	int ret;

	ret = new_style_header(net);
	if (ret < 0) {
		return NULL;
	}

	return negotiate_name(net);
}

int nbd_server_negotiate_info_new_style(int net, uint64_t size, uint32_t flags)
{
	uint16_t smallflags;
	char zeros[128];

	memset(zeros, '\0', sizeof(zeros));

	size = htonll(size);
	if (write(net, &size, sizeof(size)) < sizeof(size)) {
		return -errno;
	}

	smallflags = (uint16_t)(flags & ~((uint16_t)0));
	smallflags = htons(smallflags);
	if (write(net, &smallflags, sizeof(smallflags)) !=
					sizeof(smallflags)) {
		return -errno;
	}

	if (write(net, zeros, 124) != 124) {
		return -errno;
	}
	return 0;
}
