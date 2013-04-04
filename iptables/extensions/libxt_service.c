/*
 * Shared library add-on to iptables to match
 * packets based on KZorp services
 *
 * Copyright (C) 2006,2009 BalaBit IT Ltd.
 * Author: KOVACS Krisztian <hidden@balabit.hu>
 */
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <iptables.h>
#include <linux/netfilter/xt_service.h>

static void
service_help(void)
{
	printf(
"service v%s options:\n"
"  --service-name <svc>		match service name\n"
"  --service-type <mode>	match service type: forward | proxy\n",
XTABLES_VERSION);
}

static struct option service_opts[] = {
	{ .name = "service-name", .has_arg = true, .val = '1' },
	{ .name = "service-type", .has_arg = true, .val = '2' },
	{ .name = NULL }
};

enum {
	F_NAME = 1 << 0,
	F_TYPE = 1 << 1,
};

static int
service_parse(int c, char **argv, int invert, unsigned int *flags,
	      const void *entry, struct xt_entry_match **match)
{
	struct ipt_service_info *info =
			(struct ipt_service_info *) (*match)->data;

	switch (c) {
	case '1': /* service-name */
		if (*flags & F_NAME)
			xtables_error(PARAMETER_PROBLEM,
				   "Cannot specify `--service-name' "
				   "more than once\n");

		if (strlen(optarg) == 0)
			xtables_error(PARAMETER_PROBLEM,
				   "`--service-name' must be accompanied by "
				   "a service name\n");

		strncpy((char *)info->name, optarg, sizeof(info->name));
		info->name[IPT_SERVICE_NAME_LENGTH] = '\0';

		if (strcmp(optarg, "*") == 0)
			info->name_match = IPT_SERVICE_NAME_WILDCARD;
		else
			info->name_match = IPT_SERVICE_NAME_MATCH;

		*flags |= F_NAME;
		break;

	case '2': /* service-type */
		if (*flags & F_TYPE)
			xtables_error(PARAMETER_PROBLEM,
				  "Cannot specify `--service-type' "
				  "more than once\n");

		if ((strlen(optarg) == 0) ||
		    ((strcmp(optarg, "forward") != 0) &&
		     (strcmp(optarg, "proxy") != 0)))
			xtables_error(PARAMETER_PROBLEM,
				   "`--service-type' must be accompanied "
				   "by a valid service type\n");

		if (strcmp(optarg, "forward") == 0)
			info->type = IPT_SERVICE_TYPE_FORWARD;
		else
			info->type = IPT_SERVICE_TYPE_PROXY;

		*flags |= F_TYPE;
		break;

	default:
		return 0;
	}

	return 1;
}

static void
service_final_check(unsigned int flags)
{
	if (!(flags & (F_NAME | F_TYPE)))
		xtables_error(PARAMETER_PROBLEM,
			   "You must specify either `--service-name' "
			   "or `--service-type'\n");
}

static void
service_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
	struct ipt_service_info *info = (struct ipt_service_info *) match->data;

	fputs("service ", stdout);
	if (info->name_match != IPT_SERVICE_NAME_ANY)
		printf("name %s ", info->name);
	if (info->type != IPT_SERVICE_TYPE_ANY)
		printf("type %s ",
		       (info->type == IPT_SERVICE_TYPE_PROXY) ? "proxy "
							      : "forward ");
}

static void
service_save(const void *ip, const struct xt_entry_match *match)
{
	struct ipt_service_info *info = (struct ipt_service_info *)match->data;

	if (info->name_match != IPT_SERVICE_NAME_ANY)
		printf("--service-name %s ", info->name);
	if (info->type != IPT_SERVICE_TYPE_ANY)
		printf("--service-type %s ",
		       (info->type == IPT_SERVICE_TYPE_PROXY) ? "proxy "
							      : "forward ");
}

static struct xtables_match service = {
	.name		= "service",
	.family		= NFPROTO_UNSPEC,
	.version	= XTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct ipt_service_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct ipt_service_info)),
	.help		= service_help,
	.parse		= service_parse,
	.final_check	= service_final_check,
	.print		= service_print,
	.save		= service_save,
	.extra_opts	= service_opts
};

void _init(void)
{
	xtables_register_match(&service);
}
