#include <stdio.h>
#include <stdlib.h>

#include "getopt.h"
#include "config.h"
#include "utils.h"

static void show_usage()
{
	fputs(
		"\n", stderr);
	fputs(
		"Quilt client\n\n", stderr);
	fputs(
		"  usage:\n\n", stderr);
	fprintf(stderr,
		"    %s\n\n", progname);
	fputs(
		"       -p <server_port>           Port number of your remote server.\n", stderr);
	fputs(
		"       -m <mocking_host>          Host name of your mocking server.\n", stderr);
	fputs(
		"       -k <password>              Password of this server.\n", stderr);
	fputs(
		"       -l <local_port>            Port number of this server.\n", stderr);
	fputs(
		"\n", stderr);
	fputs(
		"       [-s <server_host>]         Host name or IP address of your remote server. Default 127.0.0.1.\n", stderr);
	fputs(
		"       [-i <mocking_ip>]          IP of your mocking server.\n", stderr);
	fputs(
		"       [-c <config_file>]         The path to config file.\n", stderr);
	fputs(
		"\n", stderr);
	fputs(
		"       [-v]                       Verbose mode.\n", stderr);
	fputs(
		"       [-h, --help]               Print this message.\n", stderr);
	fputs(
		"\n", stderr);
}

/* Vals for long options */
enum {
	GETOPT_VAL_HELP = 257
};

int parse_config(int argc, char** argv, config_t* out)
{
	const char* server_host = NULL;
	int server_port = 0;
	const char* mocking_host = NULL;
	const char* mocking_ip = NULL;
	const char* password = NULL;
	int local_port = 0;
	const char* conf_path = NULL;

	// Parse options
	static struct option long_options[] = {
		{ "help",        no_argument,       NULL, GETOPT_VAL_HELP },
		{ NULL,                          0, NULL,               0 }
	};
	int c;
	while ((c = getopt_long(argc, argv, "p:m:k:l:s:i:c:vh", long_options, NULL)) != -1)
	{
		switch (c)
		{
		case 's':
			server_host = optarg;
			break;
		case 'p':
			if (parse_int(optarg, &server_port, 10))
			{
				warnx("invalid port number -- %s", optarg);
				goto err;
			}
			break;
		case 'm':
			mocking_host = optarg;
			break;
		case 'i':
			mocking_ip = optarg;
			break;
		case 'k':
			password = optarg;
			break;
		case 'l':
			if (parse_int(optarg, &local_port, 10))
			{
				warnx("invalid port number -- %s", optarg);
				goto err;
			}
			break;
		case 'c':
			conf_path = optarg;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'h':
		case GETOPT_VAL_HELP:
			show_usage();
			return CFG_NORMAL_EXIT;
		case '?':
			goto err;
		}
	}

	// Read config file
	if (conf_path)
	{
		// TODO: read cfg
	}

	// Verify if option presents
	if (!server_port || !mocking_host || !password || !local_port)
	{
		warnx("not all required parameters are provided");
		goto err;
	}

	// Apply default value
	if (!server_host)
	{
		server_host = "127.0.0.1";
	}


	out->server_host = server_host;
	out->server_port = server_port;
	out->mocking_host = mocking_host;
	out->mocking_ip = mocking_ip;
	out->password = password;
	out->local_port = local_port;

	return CFG_NORMAL;

err:
	show_usage();
	return CFG_ERR;
}
