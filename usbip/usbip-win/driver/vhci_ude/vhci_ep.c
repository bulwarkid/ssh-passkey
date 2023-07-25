#include "vhci_driver.h"
#include "vhci_ep.tmh"
#include "devconf.h"

extern WDFQUEUE
create_queue_ep(pctx_ep_t ep);

static VOID
ep_start(_In_ UDECXUSBENDPOINT ude_ep)
{
	pctx_ep_t	ep = TO_EP(ude_ep);

	TRD(VUSB, "Enter: ep->addr=0x%x", ep->addr);
	WdfIoQueueStart(ep->queue);
	TRD(VUSB, "Leave");
}

static VOID
purge_complete(WDFQUEUE queue, WDFCONTEXT ctx)
{
	UNREFERENCED_PARAMETER(ctx);

	UdecxUsbEndpointPurgeComplete((*TO_PEP(queue))->ude_ep);
}

static VOID
ep_purge(_In_ UDECXUSBENDPOINT ude_ep)
{
	pctx_ep_t	ep = TO_EP(ude_ep);

	TRD(VUSB, "Enter: ep->addr=0x%x", ep->addr);

	/* WdfIoQueuePurgeSynchronously would suffer from blocking */
	WdfIoQueuePurge(ep->queue, purge_complete, NULL);

	TRD(VUSB, "Leave");
}

static VOID
ep_reset(_In_ UDECXUSBENDPOINT ep, _In_ WDFREQUEST req)
{
	UNREFERENCED_PARAMETER(ep);
	UNREFERENCED_PARAMETER(req);

	TRE(VUSB, "Enter");
}

static void
setup_ep_from_dscr(pctx_ep_t ep, PUSB_ENDPOINT_DESCRIPTOR dsc_ep)
{
	ep->intf_num = 0;
	ep->altsetting = 0;
	if (dsc_ep == NULL) {
		ep->type = USB_ENDPOINT_TYPE_CONTROL;
		ep->addr = USB_DEFAULT_DEVICE_ADDRESS;
		ep->interval = 0;
	}
	else {
		PUSB_INTERFACE_DESCRIPTOR	dsc_intf;

		ep->type = dsc_ep->bmAttributes & USB_ENDPOINT_TYPE_MASK;
		ep->addr = dsc_ep->bEndpointAddress;
		ep->interval = dsc_ep->bInterval;

		dsc_intf = dsc_find_intf_by_ep((PUSB_CONFIGURATION_DESCRIPTOR)ep->vusb->dsc_conf, dsc_ep);
		if (dsc_intf) {
			ep->intf_num = dsc_intf->bInterfaceNumber;
			ep->altsetting = dsc_intf->bAlternateSetting;
		}
		else {
			TRE(VUSB, "weird case: interface for ep not found");
		}
	}
}

NTSTATUS
add_ep(pctx_vusb_t vusb, PUDECXUSBENDPOINT_INIT *pepinit, PUSB_ENDPOINT_DESCRIPTOR dscr_ep)
{
	pctx_ep_t	ep;
	UDECXUSBENDPOINT	ude_ep;
	UDECX_USB_ENDPOINT_CALLBACKS	callbacks;
	WDFQUEUE	queue;
	UCHAR		ep_addr;
	WDF_OBJECT_ATTRIBUTES       attrs;
	NTSTATUS	status;

	ep_addr = dscr_ep ? dscr_ep->bEndpointAddress : USB_DEFAULT_DEVICE_ADDRESS;
	TRD(VUSB, "Enter: ep_addr=0x%x", ep_addr);
	UdecxUsbEndpointInitSetEndpointAddress(*pepinit, ep_addr);

	UDECX_USB_ENDPOINT_CALLBACKS_INIT(&callbacks, ep_reset);
	if (!vusb->is_simple_ep_alloc) {
		/*
		 * FIXME: A simple vusb stops working after a purge routine is called.
		 * The exact reason is unknown.
		 */
		callbacks.EvtUsbEndpointStart = ep_start;
		callbacks.EvtUsbEndpointPurge = ep_purge;
	}
	UdecxUsbEndpointInitSetCallbacks(*pepinit, &callbacks);

	WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attrs, ctx_ep_t);
	attrs.ParentObject = vusb->ude_usbdev;
	status = UdecxUsbEndpointCreate(pepinit, &attrs, &ude_ep);
	if (NT_ERROR(status)) {
		TRE(VUSB, "failed to create endpoint: %!STATUS!", status);
		return status;
	}

	ep = TO_EP(ude_ep);
	ep->vusb = vusb;
	ep->ude_ep = ude_ep;
	setup_ep_from_dscr(ep, dscr_ep);

	queue = create_queue_ep(ep);
	if (queue == NULL) {
		WdfObjectDelete(ude_ep);
		TRE(VUSB, "failed to create queue: STATUS_UNSUCCESSFUL");
		return STATUS_UNSUCCESSFUL;
	}
	UdecxUsbEndpointSetWdfIoQueue(ude_ep, queue);

	ep->queue = queue;
	if (dscr_ep == NULL) {
		vusb->ep_default = ep;
	}
	TRD(VUSB, "Leave");
	return STATUS_SUCCESS;
}

static NTSTATUS
default_ep_add(_In_ UDECXUSBDEVICE udev, _In_ PUDECXUSBENDPOINT_INIT epinit)
{
	pctx_vusb_t	vusb = TO_VUSB(udev);
	NTSTATUS	status;

	TRD(VUSB, "Enter");

	status = add_ep(vusb, &epinit, NULL);

	TRD(VUSB, "Leave: %!STATUS!", status);

	return status;
}

static NTSTATUS
ep_add(_In_ UDECXUSBDEVICE udev, _In_ PUDECX_USB_ENDPOINT_INIT_AND_METADATA epcreate)
{
	pctx_vusb_t	vusb = TO_VUSB(udev);
	NTSTATUS	status;

	TRD(VUSB, "Enter: epaddr: 0x%x, interval: 0x%x", (ULONG)epcreate->EndpointDescriptor->bEndpointAddress,
		(ULONG)epcreate->EndpointDescriptor->bInterval);

	status = add_ep(vusb, &epcreate->UdecxUsbEndpointInit, epcreate->EndpointDescriptor);

	TRD(VUSB, "Leave: %!STATUS!", status);

	return status;
}

static NTSTATUS
set_intf_for_ep(pctx_vusb_t vusb, WDFREQUEST req, PUDECX_ENDPOINTS_CONFIGURE_PARAMS params)
{
	UCHAR	intf_num = params->InterfaceNumber;
	UCHAR	altsetting = params->NewInterfaceSetting;

	if (params->EndpointsToConfigureCount > 0) {
		pctx_ep_t	ep = TO_EP(params->EndpointsToConfigure[0]);
		PUSB_CONFIGURATION_DESCRIPTOR	dsc_conf;
		PUSB_INTERFACE_DESCRIPTOR	dsc_intf;
		PUSB_ENDPOINT_DESCRIPTOR	dsc_ep = NULL;

		dsc_conf = (PUSB_CONFIGURATION_DESCRIPTOR)vusb->dsc_conf;
		dsc_intf = dsc_find_intf(dsc_conf, intf_num, altsetting);
		if (dsc_intf) {
			dsc_ep = dsc_find_intf_ep(dsc_conf, dsc_intf, ep->addr);
		}

		if (dsc_ep == NULL) {
			/* UDE dynamic EP configuration does not seem to provide correct values */
			/* Use the values of vhci EP which are obtained from the parent interface descriptor */
			intf_num = ep->intf_num;
			altsetting = ep->altsetting;
		}
	}

	if (vusb->intf_altsettings[intf_num] == altsetting)
		return STATUS_SUCCESS;

	vusb->intf_altsettings[intf_num] = altsetting;

	TRD(VUSB, "SELECT INTERFACE: NUM:%d Alt:%d", intf_num, altsetting);

	return submit_req_select(vusb->ep_default, req, FALSE, 0, intf_num, altsetting);
}

static VOID
ep_configure(_In_ UDECXUSBDEVICE udev, _In_ WDFREQUEST req, _In_ PUDECX_ENDPOINTS_CONFIGURE_PARAMS params)
{
	pctx_vusb_t	vusb = TO_VUSB(udev);
	NTSTATUS	status = STATUS_SUCCESS;

	TRD(VUSB, "Enter: %!epconf!", params->ConfigureType);

	switch (params->ConfigureType) {
	case UdecxEndpointsConfigureTypeDeviceInitialize:
		/* FIXME: UDE framework seems to not call SET CONFIGURATION if a USB has multiple interfaces.
		 * This enforces the device to be set with the first configuration.
		 */
		status = submit_req_select(vusb->ep_default, req, 1, vusb->default_conf_value, 0, 0);
		TRD(VUSB, "trying to SET CONFIGURATION: %u", (ULONG)vusb->default_conf_value);
		break;
	case UdecxEndpointsConfigureTypeDeviceConfigurationChange:
		status = submit_req_select(vusb->ep_default, req, 1, params->NewConfigurationValue, 0, 0);
		break;
	case UdecxEndpointsConfigureTypeInterfaceSettingChange:
		/*
		 * When a device is being detached, set_intf for the invalidated device is avoided.
		 * Error status for set_intf seems to disturb detaching.
		 */
		if (!vusb->invalid) {
			status = set_intf_for_ep(vusb, req, params);
		}
		break;
	case UdecxEndpointsConfigureTypeEndpointsReleasedOnly:
		break;
	default:
		TRE(VUSB, "unhandled configure type: %!epconf!", params->ConfigureType);
		break;
	}

	if (status != STATUS_PENDING)
		WdfRequestComplete(req, status);
	TRD(VUSB, "Leave: %!STATUS!", status);
}

VOID
setup_ep_callbacks(PUDECX_USB_DEVICE_STATE_CHANGE_CALLBACKS pcallbacks)
{
	pcallbacks->EvtUsbDeviceDefaultEndpointAdd = default_ep_add;
	pcallbacks->EvtUsbDeviceEndpointAdd = ep_add;
	pcallbacks->EvtUsbDeviceEndpointsConfigure = ep_configure;
}
