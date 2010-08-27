#include "config.h"

#include <unistd.h>
#include "libnbd.h"

/**
 * Read data from a file descriptor into a buffer
 *
 * @param f a file descriptor
 * @param buf a buffer
 * @param len the number of bytes to be read
 **/

static inline int readit(int f, void *buf, size_t len)
{
	ssize_t res;
	while (len > 0) {
		if ((res = read(f, buf, len)) <= 0) {
			if(errno != EAGAIN) {
				return -errno;
			}
		} else {
			len -= res;
			buf += res;
		}
	}
	return 0;
}

/**
 * Write data from a buffer into a filedescriptor
 *
 * @param f a file descriptor
 * @param buf a buffer containing data
 * @param len the number of bytes to be written
 **/

static inline int writeit(int f, void *buf, size_t len)
{
	ssize_t res;
	while (len > 0) {
		if ((res = write(f, buf, len)) <= 0) {
			return -errno;
		}
		len -= res;
		buf += res;
	}
	return 0;
}

static int nbd_server_receive(int net, struct nbd_request *request)
{
	int ret;
	/*
	 * magic[4]	NBD_REQUEST_MAGIC	(0x25609513)
	 * type[4]	0			(READ)
	 *		1			(WRITE)
	 * handle[8]
	 * from[8]
	 * len[4]
	 */

	ret = readit(net, request, sizeof(*request));
	if (ret < 0)
		return ret;

	request->magic = htonl(request->magic);
	request->type = ntohl(request->type);
	request->from = ntohll(request->from);
	request->len = ntohl(request->len);

	if (request->magic != NBD_REQUEST_MAGIC) {
		return -EINVAL;
	}

	return 0;
}

int nbd_server_loop(CLIENT *client, char *buf, int len)
{
	int ret;
	struct nbd_request request;
	struct nbd_reply reply;

	/*
	 * magic[4]	NBD_REPLY_MAGIC		(0x67446698)
	 * error[4]	errno
	 * handle[8]
	 */

	reply.magic = htonl(NBD_REPLY_MAGIC);
	reply.error = 0;

	ret = nbd_server_receive(client->net, &request);
	if (ret < 0)
		return ret;

	memcpy(reply.handle, request.handle, sizeof(reply.handle));

	if (request.len + sizeof(reply) > len) {
		return -EINVAL;
	}

	if ((request.from + request.len) > (OFFT_MAX)) {
		reply.error = htonl(EINVAL);
		return writeit(client->net, &reply, sizeof(reply));
	}

	if (((ssize_t)((off_t)request.from + request.len) >
						client->exportsize)) {
		reply.error = htonl(EINVAL);
		return writeit(client->net, &reply, sizeof(reply));
	}

	switch(request.type) {
		case NBD_CMD_DISC:
			return 1;

		case NBD_CMD_WRITE:
			ret = readit(client->net, buf, request.len);
			if (ret < 0)
				return ret;

			if ((client->server->flags & F_READONLY) ||
			    (client->server->flags & F_AUTOREADONLY)) {
				reply.error = htonl(EPERM);
				return writeit(client->net, &reply,
					       sizeof(reply));
			}

			if (expwrite(request.from, buf, request.len, client)) {
				reply.error = htonl(errno);
			}

			return writeit(client->net, &reply, sizeof(reply));

		case NBD_CMD_READ:

			if (expread(request.from, buf + sizeof(reply),
				    request.len, client)) {
				reply.error = htonl(errno);
				return writeit(client->net, &reply,
					       sizeof(reply));
			}

			memcpy(buf, &reply, sizeof(reply));
			return writeit(client->net, buf,
				       request.len + sizeof(reply));
	}

	return -EINVAL;
}
