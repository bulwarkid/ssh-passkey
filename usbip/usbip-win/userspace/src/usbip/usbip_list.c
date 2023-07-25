/*
 * Copyright (C) 2011 matt mooney <mfm@muteddisk.com>
 *               2005-2007 Takahiro Hirofuchi
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <ws2tcpip.h>

#include "usbip_common.h"
#include "usbip_network.h"

#include "usbip_windows.h"
#include "usbip_setupdi.h"

int list_devices(BOOL parsable);
int list_exported_devices(const char *host);

static const char usbip_list_usage_string[] =
	"usbip list [-p|--parsable] <args>\n"
	"    -p, --parsable         Parsable list format\n"
	"    -r, --remote=<host>    List the exported USB devices on <host>\n"
	"    -l, --local            List the local USB devices\n"
	;

void usbip_list_usage(void)
{
	printf("usage: %s", usbip_list_usage_string);
}

int usbip_list(int argc, char *argv[])
{
	static const struct option opts[] = {
		{ "parsable", no_argument, NULL, 'p' },
		{ "remote", required_argument, NULL, 'r' },
		{ "local", no_argument, NULL, 'l' },
		{ NULL, 0, NULL, 0 }
	};
	BOOL parsable = FALSE;
	int opt;
	int ret = 1;

	if (usbip_names_init() != 0)
		dbg("failed to open usb id database");

	for (;;) {
		opt = getopt_long(argc, argv, "pr:l", opts, NULL);

		if (opt == -1)
			break;

		switch (opt) {
		case 'p':
			parsable = TRUE;
			break;
		case 'r':
			ret = list_exported_devices(optarg);
			goto out;
		case 'l':
			ret = list_devices(parsable);
			goto out;
		default:
			break;
		}
	}

	err("-r or -l option required");
	usbip_list_usage();
out:
	usbip_names_free();

	return ret;
}
