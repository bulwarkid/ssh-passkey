#pragma once

#pragma pack(push,1)

/*
 * USB/IP request headers.
 * Currently, we define 4 request types:
 *
 *  - CMD_SUBMIT transfers a USB request, corresponding to usb_submit_urb().
 *    (client to server)
 *  - RET_RETURN transfers the result of CMD_SUBMIT.
 *    (server to client)
 *  - CMD_UNLINK transfers an unlink request of a pending USB request.
 *    (client to server)
 *  - RET_UNLINK transfers the result of CMD_UNLINK.
 *    (server to client)
 *
 * Note: The below request formats are based on the USB subsystem of Linux. Its
 * details will be defined when other implementations come.
 *
 *
 */

struct usbip_header_basic {
#define USBIP_CMD_SUBMIT	0x0001
#define USBIP_CMD_UNLINK	0x0002
#define USBIP_RET_SUBMIT	0x0003
#define USBIP_RET_UNLINK	0x0004
#define USBIP_RESET_DEV		0xFFFF
	UINT32	command;

	/* sequencial number which identifies requests.
	* incremented per connections */
	UINT32	seqnum;

	/* devid is used to specify a remote USB device uniquely instead
	 * of busnum and devnum in Linux. In the case of Linux stub_driver,
	 * this value is ((busnum << 16) | devnum) */
	UINT32	devid;

#define USBIP_DIR_OUT	0
#define USBIP_DIR_IN	1
	UINT32	direction;
	UINT32	ep;     /* endpoint number */
};

/*
* An additional header for a CMD_SUBMIT packet.
*/
struct usbip_header_cmd_submit {
	/* these values are basically the same as in a URB. */

	/* the same in a URB. */
	UINT32	transfer_flags;

	/* set the following data size (out),
	* or expected reading data size (in) */
	INT32	transfer_buffer_length;

	/* it is difficult for usbip to sync frames (reserved only?) */
	INT32	start_frame;

	/* the number of iso descriptors that follows this header */
	INT32	number_of_packets;

	/* the maximum time within which this request works in a host
	* controller of a server side */
	INT32	interval;

	/* set setup packet data for a CTRL request */
	UINT8	setup[8];
};

/*
* An additional header for a RET_SUBMIT packet.
*/
struct usbip_header_ret_submit {
	INT32	status;
	INT32	actual_length; /* returned data length */
	INT32	start_frame; /* ISO and INT */
	INT32	number_of_packets;  /* ISO only */
	INT32	error_count; /* ISO only */
};

/*
* An additional header for a CMD_UNLINK packet.
*/
struct usbip_header_cmd_unlink {
	UINT32	seqnum; /* URB's seqnum which will be unlinked */
};

/*
* An additional header for a RET_UNLINK packet.
*/
struct usbip_header_ret_unlink {
	INT32	status;
};

/* the same as usb_iso_packet_descriptor but packed for pdu */
struct usbip_iso_packet_descriptor {
	UINT32	offset;
	UINT32	length;            /* expected length */
	UINT32	actual_length;
	UINT32	status;
};

/*
* All usbip packets use a common header to keep code simple.
*/
struct usbip_header {
	struct usbip_header_basic base;

	union {
		struct usbip_header_cmd_submit	cmd_submit;
		struct usbip_header_ret_submit	ret_submit;
		struct usbip_header_cmd_unlink	cmd_unlink;
		struct usbip_header_ret_unlink	ret_unlink;
	} u;
};

#pragma pack(pop)

enum usb_device_speed {
	USB_SPEED_UNKNOWN = 0,			/* enumerating */
	USB_SPEED_LOW, USB_SPEED_FULL,		/* usb 1.1 */
	USB_SPEED_HIGH,				/* usb 2.0 */
	USB_SPEED_WIRELESS,			/* wireless (usb 2.5) */
	USB_SPEED_SUPER,			/* usb 3.0 */
	USB_SPEED_SUPER_PLUS			/* usb 3.1 */
};