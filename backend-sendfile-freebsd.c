/*
 * sendfile-freebsd.c -- serve data by using sendfile(), FreeBSD-style
 * Copyright(c) Wouter Verhelst, 2007
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include <glib.h>
#include <nbd-server.h>

ssize_t backend_read(int fh, int net, off_t offset, size_t len) {
	if(sendfile(fhandle, client->net, foffset, len, NULL, &retval, 0)) {
		return -1;
	} else {
		return (ssize_t)retval;
	}
}