#pragma once

#include <ntddk.h>
#include <wdf.h>
#include <usbdi.h>

#include "usb_util.h"

#include "vhci_dev.h"

typedef enum {
	URBR_TYPE_URB,
	URBR_TYPE_UNLINK,
	URBR_TYPE_SELECT_CONF,
	URBR_TYPE_SELECT_INTF,
	URBR_TYPE_RESET_PIPE
} urbr_type_t;

typedef struct _urb_req {
	pctx_ep_t	ep;
	WDFREQUEST	req;
	urbr_type_t	type;
	unsigned long	seq_num;
	union {
		struct {
			PURB	urb;
			BOOLEAN	cancelable;
		} urb;
		unsigned long	seq_num_unlink;
		UCHAR	conf_value;
		struct {
			UCHAR	intf_num, alt_setting;
		} intf;
	} u;
	LIST_ENTRY	list_all;
	LIST_ENTRY	list_state;
	/* back reference to WDFMEMORY for deletion */
	WDFMEMORY	hmem;
} urb_req_t, *purb_req_t;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(urb_req_t, TO_URBR)

#define IS_TRANSFER_FLAGS_IN(flags)	((flags) & USBD_TRANSFER_DIRECTION_IN)

#define RemoveEntryListInit(le)	do { RemoveEntryList(le); InitializeListHead(le); } while (0)

extern struct usbip_header *get_hdr_from_req_read(WDFREQUEST req_read);
extern PVOID get_data_from_req_read(WDFREQUEST req_read, ULONG length);

extern ULONG get_read_payload_length(WDFREQUEST req_read);

extern PVOID get_buf(PVOID buf, PMDL bufMDL);

extern NTSTATUS
copy_to_transfer_buffer(PVOID buf_dst, PMDL bufMDL, int dst_len, PVOID src, int src_len);

extern void set_cmd_submit_usbip_header(struct usbip_header *hdr, unsigned long seqnum, unsigned int devid,
	unsigned int direct, pctx_ep_t ep, unsigned int flags, unsigned int len);
extern void set_cmd_unlink_usbip_header(struct usbip_header *h, unsigned long seqnum, unsigned int devid,
	unsigned long seqnum_unlink);

extern void
build_setup_packet(usb_cspkt_t *csp, unsigned char direct_in, unsigned char type, unsigned char recip, unsigned char request);

extern NTSTATUS
submit_req_urb(pctx_ep_t ep, WDFREQUEST req);
extern NTSTATUS
submit_req_select(pctx_ep_t ep, WDFREQUEST req, BOOLEAN is_select_conf, UCHAR conf_value, UCHAR intf_num, UCHAR alt_setting);
extern NTSTATUS
submit_req_reset_pipe(pctx_ep_t ep, WDFREQUEST req);
extern NTSTATUS
store_urbr(WDFREQUEST req_read, purb_req_t urbr);

extern BOOLEAN
unmark_cancelable_urbr(purb_req_t urbr);
extern void
complete_urbr(purb_req_t urbr, NTSTATUS status);
