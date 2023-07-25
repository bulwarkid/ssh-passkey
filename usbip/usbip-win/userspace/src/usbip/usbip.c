/*
 * command structure borrowed from udev
 * (git://git.kernel.org/pub/scm/linux/hotplug/udev.git)
 *
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

#include <stdlib.h>

#include "usbip_windows.h"

#include "usbip_common.h"
#include "usbip_network.h"
#include "usbip.h"

static int usbip_help(int argc, char *argv[]);
static int usbip_version(int argc, char *argv[]);

static const char usbip_version_string[] = PACKAGE_STRING;

static const char usbip_usage_string[] =
	"usbip [--debug] [--tcp-port PORT] [version]\n"
	"             [help] <command> <args>\n";

static void usbip_usage(void)
{
	printf("usage: %s", usbip_usage_string);
}

struct command {
	const char *name;
	int (*fn)(int argc, char *argv[]);
	const char *help;
	void (*usage)(void);
};

static const struct command cmds[] = {
	{
		.name  = "help",
		.fn    = usbip_help,
		.help  = NULL,
		.usage = NULL
	},
	{
		.name  = "version",
		.fn    = usbip_version,
		.help  = NULL,
		.usage = NULL
	},
	{
		.name  = "attach",
		.fn    = usbip_attach,
		.help  = "Attach a remote USB device(WDM or ude)",
		.usage = usbip_attach_usage
	},
	{
		.name  = "detach",
		.fn    = usbip_detach,
		.help  = "Detach a remote USB device",
		.usage = usbip_detach_usage
	},
	{
		.name  = "list",
		.fn    = usbip_list,
		.help  = "List exportable or local USB devices",
		.usage = usbip_list_usage
	},
	{
		.name  = "bind",
		.fn    = usbip_bind,
		.help  = "Bind device to usbip stub driver",
		.usage = usbip_bind_usage
	},
	{
		.name  = "unbind",
		.fn    = usbip_unbind,
		.help  = "Unbind device from usbip stub driver",
		.usage = usbip_unbind_usage
	},
	{
		.name  = "install",
		.fn    = usbip_install,
		.help  = "Install usbip vhci driver",
		.usage = usbip_install_usage
	},
	{
		.name = "uninstall",
		.fn = usbip_uninstall,
		.help = "Uninstall usbip vhci driver",
		.usage = usbip_uninstall_usage
	},
	{
		.name  = "port",
		.fn    = usbip_port_show,
		.help  = "Show imported USB devices",
		.usage = usbip_port_usage
	},
	{ NULL, NULL, NULL, NULL }
};

static int usbip_help(int argc, char *argv[])
{
	const struct command *cmd;

	if (argc > 1) {
		int	i;

		for (i = 0; cmds[i].name != NULL; i++)
			if (strcmp(cmds[i].name, argv[1]) == 0) {
				if (cmds[i].usage)
					cmds[i].usage();
				else
					printf("no help for command: %s\n", argv[1]);
				return 0;
			}
		err("no help for invalid command: %s", argv[1]);
		return 1;
	}

	usbip_usage();
	printf("\n");
	for (cmd = cmds; cmd->name != NULL; cmd++)
		if (cmd->help != NULL)
			printf("  %-10s %s\n", cmd->name, cmd->help);
	printf("\n");
	return 0;
}

static int usbip_version(int argc, char *argv[])
{
	printf("usbip (%s)\n", usbip_version_string);
	return 0;
}

static int run_command(const struct command *cmd, int argc, char *argv[])
{
	dbg("running command: %s", cmd->name);
	return cmd->fn(argc, argv);
}

int main(int argc, char *argv[])
{
	static const struct option opts[] = {
		{ "debug",    no_argument,       NULL, 'd' },
		{ "tcp-port", required_argument, NULL, 't' },
		{ NULL,       0,                 NULL,  0 }
	};

	char	*cmd;
	int	opt;
	int	rc = 1;

	usbip_progname = "usbip";
	usbip_use_stderr = 1;

	opterr = 0;
	for (;;) {
		opt = getopt_long(argc, argv, "+dt:", opts, NULL);

		if (opt == -1)
			break;

		switch (opt) {
		case 'd':
			usbip_use_debug = 1;
			break;
		case 't':
			usbip_setup_port_number(optarg);
			break;
		case '?':
			err("invalid option: %c", opt);
			/* fall through */
		default:
			usbip_usage();
			return 1;
		}
	}

	if (init_socket() < 0) {
		err("cannot setup windows socket");
		return EXIT_FAILURE;
	}

	cmd = argv[optind];
	if (cmd) {
		int	i;

		for (i = 0; cmds[i].name != NULL; i++)
			if (!strcmp(cmds[i].name, cmd)) {
				argc -= optind;
				argv += optind;
				optind = 0;
				rc = run_command(&cmds[i], argc, argv);
				goto out;
			}
		err("invalid command: %s", cmd);
	}
	else {
		/* empty command */
		usbip_help(0, NULL);
	}

out:
	cleanup_socket();
	return rc;
}
