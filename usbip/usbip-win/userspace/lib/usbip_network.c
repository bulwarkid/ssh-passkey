/*
 *
 * Copyright (C) 2005-2007 Takahiro Hirofuchi
 */

#include <ws2tcpip.h>
#include <mstcpip.h>

#include "usbip_common.h"
#include "usbip_network.h"
#include "dbgcode.h"

int usbip_port = 3240;
char *usbip_port_string = "3240";

void usbip_setup_port_number(char *arg)
{
	char *end;
	unsigned long int port = strtoul(arg, &end, 10);

	if (end == arg) {
		dbg("port: could not parse '%s' as a decimal integer", arg);
		return;
	}

	if (*end != '\0') {
		dbg("port: garbage at end of '%s'", arg);
		return;
	}

	if (port > UINT16_MAX) {
		dbg("port: %s too high (max=%d)",
		    arg, UINT16_MAX);
		return;
	}

	usbip_port = port;
	usbip_port_string = arg;
	info("using port %d (\"%s\")", usbip_port, usbip_port_string);
}

void usbip_net_pack_uint32_t(int pack, uint32_t *num)
{
	uint32_t i;

	if (pack)
		i = htonl(*num);
	else
		i = ntohl(*num);

	*num = i;
}

void usbip_net_pack_uint16_t(int pack, uint16_t *num)
{
	uint16_t i;

	if (pack)
		i = htons(*num);
	else
		i = ntohs(*num);

	*num = i;
}

void usbip_net_pack_usb_device(int pack, struct usbip_usb_device *udev)
{
	usbip_net_pack_uint32_t(pack, &udev->busnum);
	usbip_net_pack_uint32_t(pack, &udev->devnum);
	usbip_net_pack_uint32_t(pack, &udev->speed);

	usbip_net_pack_uint16_t(pack, &udev->idVendor);
	usbip_net_pack_uint16_t(pack, &udev->idProduct);
	usbip_net_pack_uint16_t(pack, &udev->bcdDevice);
}

void usbip_net_pack_usb_interface(int pack, struct usbip_usb_interface *udev)
{
	UNREFERENCED_PARAMETER(pack);
	UNREFERENCED_PARAMETER(udev);
	/* uint8_t members need nothing */
}

static int usbip_net_xmit(SOCKET sockfd, void *buff, size_t bufflen, int sending)
{
	int total = 0;

	if (!bufflen)
		return 0;

	do {
		int nbytes;

		if (sending)
			nbytes = send(sockfd, buff, (int)bufflen, 0);
		else
			nbytes = recv(sockfd, buff, (int)bufflen, 0);

		if (nbytes <= 0)
			return -1;

		buff	= (void *) ((intptr_t) buff + nbytes);
		bufflen	-= nbytes;
		total	+= nbytes;
	} while (bufflen > 0);

	return total;
}

int usbip_net_recv(SOCKET sockfd, void *buff, size_t bufflen)
{
	return usbip_net_xmit(sockfd, buff, bufflen, 0);
}

int usbip_net_send(SOCKET sockfd, void *buff, size_t bufflen)
{
	return usbip_net_xmit(sockfd, buff, bufflen, 1);
}

int usbip_net_send_op_common(SOCKET sockfd, uint32_t code, uint32_t status)
{
	struct op_common op_common;
	int rc;

	memset(&op_common, 0, sizeof(op_common));

	op_common.version = USBIP_VERSION;
	op_common.code    = code;
	op_common.status  = status;

	PACK_OP_COMMON(1, &op_common);

	rc = usbip_net_send(sockfd, &op_common, sizeof(op_common));
	if (rc < 0) {
		dbg("usbip_net_send failed: %d", rc);
		return -1;
	}

	return 0;
}

int usbip_net_recv_op_common(SOCKET sockfd, uint16_t *code, int *pstatus)
{
	struct op_common op_common;
	int rc;

	memset(&op_common, 0, sizeof(op_common));

	rc = usbip_net_recv(sockfd, &op_common, sizeof(op_common));
	if (rc < 0) {
		dbg("usbip_net_recv failed: %d", rc);
		return ERR_NETWORK;
	}

	PACK_OP_COMMON(0, &op_common);

	if (op_common.version != USBIP_VERSION) {
		dbg("version mismatch: %d != %d", op_common.version, USBIP_VERSION);
		return ERR_VERSION;
	}

	switch (*code) {
	case OP_UNSPEC:
		break;
	default:
		if (op_common.code != *code) {
			dbg("unexpected pdu %#0x for %#0x", op_common.code, *code);
			return ERR_PROTOCOL;
		}
	}

	*pstatus = op_common.status;

	if (op_common.status != ST_OK) {
		dbg("request failed: status: %s", dbg_opcode_status(op_common.status));
		return ERR_STATUS;
	}

	*code = op_common.code;
	return 0;
}

int usbip_net_set_reuseaddr(SOCKET sockfd)
{
	const int val = 1;
	int ret;

	ret = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char *)&val, sizeof(val));
	if (ret < 0)
		dbg("setsockopt: SO_REUSEADDR");

	return ret;
}

int usbip_net_set_nodelay(SOCKET sockfd)
{
	const int val = 1;
	int ret;

	ret = setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (void*)&val, sizeof(val));
	if (ret < 0)
		dbg("setsockopt: TCP_NODELAY");

	return ret;
}

unsigned
get_keepalive_timeout(void)
{
	char	env_timeout[32];
	unsigned	timeout;
	size_t	reqsize;

	if (getenv_s(&reqsize, env_timeout, 32, "KEEPALIVE_TIMEOUT") != 0)
		return 0;

	if (sscanf_s(env_timeout, "%u", &timeout) == 1)
		return timeout;
	return 0;
}

int usbip_net_set_keepalive(SOCKET sockfd)
{
	unsigned	timeout;

	timeout = get_keepalive_timeout();
	if (timeout > 0) {
		struct tcp_keepalive	keepalive;
		DWORD	outlen;
		int	ret;

		/* windows tries 10 times every keepaliveinterval */
		keepalive.onoff = 1;
		keepalive.keepalivetime = timeout * 1000 / 2;
		keepalive.keepaliveinterval = timeout * 1000 / 10 / 2;

		ret = WSAIoctl(sockfd, SIO_KEEPALIVE_VALS, &keepalive, sizeof(keepalive), NULL, 0, &outlen, NULL, NULL);
		if (ret != 0) {
			dbg("failed to set KEEPALIVE via SIO_KEEPALIVE_VALS: 0x%lx", GetLastError());
			return -1;
		}
		return 0;
	}
	else {
		DWORD	val = 1;
		int	ret;

		ret = setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, (void *)&val, sizeof(val));
		if (ret < 0) {
			dbg("failed to set KEEPALIVE via setsockopt: 0x%lx", GetLastError());
		}
		return ret;
	}
}

int usbip_net_set_v6only(SOCKET sockfd)
{
	const int val = 1;
	int ret;

	ret = setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&val, sizeof(val));
	if (ret < 0)
		dbg("setsockopt: IPV6_V6ONLY");

	return ret;
}

/*
 * IPv6 Ready
 */
SOCKET usbip_net_tcp_connect(const char *hostname, const char *port)
{
	struct addrinfo hints, *res, *rp;
	SOCKET sockfd = INVALID_SOCKET;
	int ret;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	/* get all possible addresses */
	ret = getaddrinfo(hostname, port, &hints, &res);
	if (ret < 0) {
		dbg("getaddrinfo: %s port %s: %s", hostname, port,
		    gai_strerror(ret));
		return INVALID_SOCKET;
	}

	/* try the addresses */
	for (rp = res; rp; rp = rp->ai_next) {
		sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sockfd == INVALID_SOCKET)
			continue;

		/* should set TCP_NODELAY for usbip */
		usbip_net_set_nodelay(sockfd);
		/* TODO: write code for heartbeat */
		usbip_net_set_keepalive(sockfd);

		if (connect(sockfd, rp->ai_addr, (int)rp->ai_addrlen) == 0)
			break;

		closesocket(sockfd);
	}

	freeaddrinfo(res);

	if (!rp)
		return INVALID_SOCKET;

	return sockfd;
}
