lib_LIBRARIES = libnbd.a 
libnbd_a_SOURCES = nbd_server_negotiate_old_style.c \
		   nbd_server_negotiate_new_style.c nbd_server_loop.c \
		   nbd_client_set_timeout.c \ nbd_client_setsizes.c \
		   nbd_client_finish_sock.c nbd_client_disconnect.c \
		   nbd_client_clear.c nbd_client_do.c nbd_client_negotiate.c
CFLAGS = -Wall -Werror @GLIB_CFLAGS@
