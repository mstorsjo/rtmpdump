#ifndef __RTMP_SYS_H__
#define __RTMP_SYS_H__
/*
 *      Copyright (C) 2010 Howard Chu
 *
 *  This file is part of librtmp.
 *
 *  librtmp is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as
 *  published by the Free Software Foundation; either version 2.1,
 *  or (at your option) any later version.
 *
 *  librtmp is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with librtmp see the file COPYING.  If not, write to
 *  the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *  http://www.gnu.org/copyleft/lgpl.html
 */

#ifdef WIN32
#include <winsock2.h>
#define GetSockError()	WSAGetLastError()
#define setsockopt(a,b,c,d,e)	(setsockopt)(a,b,c,(const char *)d,(int)e)
#define EWOULDBLOCK	WSAETIMEDOUT	/* we don't use nonblocking, but we do use timeouts */
#define sleep(n)	Sleep(n*1000)
#define msleep(n)	Sleep(n)
#define socklen_t	int
#define SET_RCVTIMEO(tv,s)	int tv = s*1000
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/times.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#define GetSockError()	errno
#undef closesocket
#define closesocket(s)	close(s)
#define msleep(n)	usleep(n*1000)
#define SET_RCVTIMEO(tv,s)	struct timeval tv = {s,0}
#endif

#include "rtmp.h"

#ifdef USE_GNUTLS
#include <gnutls/gnutls.h>
typedef struct tls_ctx {
	gnutls_certificate_credentials_t cred;
	gnutls_priority_t prios;
} tls_ctx;
#define TLS_CTX	tls_ctx *
#define TLS_client(ctx,s)	gnutls_init((gnutls_session_t *)(&s), GNUTLS_CLIENT); gnutls_priority_set(s, ctx->prios); gnutls_credentials_set(s, GNUTLS_CRD_CERTIFICATE, ctx->cred)
#define TLS_setfd(s,fd)	gnutls_transport_set_ptr(s, (gnutls_transport_ptr_t)(long)fd)
#define TLS_connect(s)	gnutls_handshake(s)
#define TLS_read(s,b,l)	gnutls_record_recv(s,b,l)
#define TLS_write(s,b,l)	gnutls_record_send(s,b,l)
#define TLS_shutdown(s)	gnutls_bye(s, GNUTLS_SHUT_RDWR)
#define TLS_close(s)	gnutls_deinit(s)
#else
#define TLS_CTX	SSL_CTX *
#define TLS_client(ctx,s)	s = SSL_new(ctx)
#define TLS_setfd(s,fd)	SSL_set_fd(s,fd)
#define TLS_connect(s)	SSL_connect(s)
#define TLS_read(s,b,l)	SSL_read(s,b,l)
#define TLS_write(s,b,l)	SSL_write(s,b,l)
#define TLS_shutdown(s)	SSL_shutdown(s)
#define TLS_close(s)	SSL_free(s)

#endif
#endif
