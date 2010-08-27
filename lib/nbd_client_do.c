#include "config.h"
#include "libnbd.h"

int nbd_client_do(int nbd)
{
	return ioctl(nbd, NBD_DO_IT);
}
