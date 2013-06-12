/*
 * Copyright (C) 2006-2012, BalaBit IT Ltd.
 * This program/include file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program/include file is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation,Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <inttypes.h>

#define PORT 12345
#define KZ_ATTR_NAME_MAX_LENGTH 1023
#define IP_TRANSPARENT 19
#define SO_KZORP_RESULT 1678333

struct kz_lookup_result {
	u_int64_t cookie;
	char czone_name[KZ_ATTR_NAME_MAX_LENGTH + 1];
	char szone_name[KZ_ATTR_NAME_MAX_LENGTH + 1];
	char dispatcher_name[KZ_ATTR_NAME_MAX_LENGTH + 1];
	char service_name[KZ_ATTR_NAME_MAX_LENGTH + 1];
};

int make_socket(uint16_t port)
{
	int sock, flag = 1;
	struct sockaddr_in name;

	/* Create the socket. */
	sock = socket(PF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	/* Set the reuse flag. */
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag))
	    < 0) {
		perror("setsockopt(SOL_SOCKET, SO_REUSEADDR)");
		exit(EXIT_FAILURE);
	}

	/* Set the transparent flag. */
	if (setsockopt(sock, SOL_IP, IP_TRANSPARENT, &flag, sizeof(flag)) <
	    0) {
		perror("setsockopt(SOL_IP, IP_TRANSPARENT)");
		exit(EXIT_FAILURE);
	}

	/* Give the socket a name. */
	name.sin_family = AF_INET;
	name.sin_port = htons(port);
	name.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(sock, (struct sockaddr *) &name, sizeof(name)) < 0) {
		perror("bind");
		exit(EXIT_FAILURE);
	}

	return sock;
}

void print_kzorp_result(int sock)
{
	struct kz_lookup_result buf;
	socklen_t size;

	size = sizeof(buf);
	if (getsockopt(sock, SOL_IP, SO_KZORP_RESULT, &buf, &size) < 0) {
		perror("getsockopt(SOL_IP, SO_KZORP_RESULT)");
		exit(EXIT_FAILURE);
	} else {
		fprintf(stderr,
			"Cookie: %" PRIu64
			", client zone: '%s', server zone: '%s', dispatcher: '%s', service: '%s'\n",
			buf.cookie, buf.czone_name, buf.szone_name,
			buf.dispatcher_name, buf.service_name);
	}
}

int main(void)
{
	int sock, new;
	struct sockaddr_in clientname;
	socklen_t size;

	sock = make_socket(PORT);
	if (listen(sock, 1) < 0) {
		perror("listen");
		exit(EXIT_FAILURE);
	}

	fprintf(stderr, "Listening on port %d\n", PORT);

	size = sizeof(clientname);
	new = accept(sock, (struct sockaddr *) &clientname, &size);
	if (new < 0) {
		perror("accept");
		exit(EXIT_FAILURE);
	}

	fprintf(stderr, "Connect from %s:%hu\n",
		inet_ntoa(clientname.sin_addr),
		ntohs(clientname.sin_port));

	print_kzorp_result(new);

	close(new);
	close(sock);

	exit(EXIT_SUCCESS);
}
