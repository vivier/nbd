#define NBD_AUTHSZ (0x100)	/* 0x100 = 256 */
typedef enum {
	NBD_WHO_SERVER,
	NBD_WHO_CLIENT,
} who_am_i;
#define NBD_WHO_SERVER (0)
#define NBD_WHO_CLIENT (1)
void nbd_auth(int sock, char *password, who_am_i who);
