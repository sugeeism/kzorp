/*
 * Shared library add-on to iptables to match
 * packets based on KZorp zones
 *
 * Copyright (C) 2006-2009, BalaBit IT Ltd.
 * Author: KOVACS Krisztian <hidden@balabit.hu>,
 *         TOTH Laszlo Attila <panther@balabit.hu>
 */
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <iptables.h>
#include <linux/netfilter/xt_zone.h>

static void zone_help_v0(void)
{
	printf(
"zone v%s options:\n"
" --src-zone zone	Match source zone\n"
" --dst-zone zone	Match destination zone\n"
" --children		Administrative children should match, too\n"
" --umbrella		Do not cross umbrella boundaries\n"
"NOTE: this kernel doesn't support multiple zones\n",
XTABLES_VERSION);
}

static void zone_help_v1(void)
{
	printf(
"zone v%s options:\n"
" --source-zones zone[,zone,zone,...]\n"
" --src-zones ...\n"
" --szones ...\n"
"			Match source zone(s)\n"
" --destination-zone zone[,zone,zone,...]\n"
" --dst-zones ...\n"
" --dzones ...\n"
"			Match destination zone(s)\n"
"  --children		Administrative children should match, too\n"
"  --umbrella		Do not cross umbrella boundaries\n",
XTABLES_VERSION);
}

static struct option zone_opts_v0[] = {
	{ .name = "src-zone", .has_arg = true, .val = '1' },
	{ .name = "dst-zone", .has_arg = true, .val = '2' },
	{ .name = "children", .has_arg = false, .val = '3' },
	{ .name = "umbrella", .has_arg = false, .val = '4' },
	{ .name = NULL }
};

static struct option zone_opts_v1[] = {
	{ .name = "source-zones", .has_arg = true, .val = '1' },
	{ .name = "src-zones", .has_arg = true, .val = '1' },
	{ .name = "src-zone", .has_arg = true, .val = '1' }, /* For backward compatibility */
	{ .name = "szones", .has_arg = true, .val = '1' },
	{ .name = "destination-zones", .has_arg = true, .val = '2' },
	{ .name = "dst-zones", .has_arg = true, .val = '2' },
	{ .name = "dst-zone", .has_arg = true, .val = '2' }, /* For backward compatibility */
	{ .name = "dzones", .has_arg = true, .val = '2' },
	{ .name = "children", .has_arg = false, .val = '3' },
	{ .name = "umbrella", .has_arg = false, .val = '4' },
	{ .name = NULL }
};

static unsigned int
parse_zone_names(const char *zonestring, struct ipt_zone_info_v1 *info, size_t max_length)
{
	char *buffer, *cp, *next;
	unsigned int i;

	buffer = strdup(zonestring);
	if (!buffer) xtables_error(OTHER_PROBLEM, "strdup failed");

	for (cp=buffer, i=0; cp && i<IPT_ZONE_NAME_COUNT; cp=next,++i) {
		next=strchr(cp, ',');
		if (next) *next++='\0';

		while (isspace(*cp)) cp++;

		strncpy((char *)info->names[i], cp, max_length);
		info->names[i][max_length] = '\0';
	}
	if (cp) xtables_error(PARAMETER_PROBLEM, "too many zones specified");
	free(buffer);
	return i;
}

enum {
	F_SRC = 1 << 0,
	F_DST = 1 << 1,
	F_CHILDREN = 1 << 2,
	F_UMBRELLA = 1 << 3,
};

static int
zone_parse_v0(int c, char **argv, int invert, unsigned int *flags,
	      const void *entry, struct xt_entry_match **match)
{
	struct ipt_zone_info *info = (struct ipt_zone_info *) (*match)->data;

	switch (c)
	{
	case '1': /* src-zone */
		if (*flags & F_SRC)
			xtables_error(PARAMETER_PROBLEM,
			           "Cannot specify `--src-zone' "
				   "more than once\n");
		if (*flags & F_DST)
			xtables_error(PARAMETER_PROBLEM,
				   "Cannot specify `--src-zone' "
				   "together with `--dst-zone'\n");

		if (strlen(optarg) == 0)
			xtables_error(PARAMETER_PROBLEM,
			           "`--src-zone' must be accompanied by "
				   "a zone name\n");

		strncpy((char *)info->name, optarg, sizeof(info->name));
		info->name[IPT_ZONE_NAME_LENGTH] = '\0';
		info->flags |= IPT_ZONE_SRC;

		*flags |= F_SRC;
		break;

	case '2': /* dst-zone */
		if (*flags & F_DST)
			xtables_error(PARAMETER_PROBLEM,
				   "Cannot specify `--dst-zone' "
				   "more than once\n");
		if (*flags & F_SRC)
			xtables_error(PARAMETER_PROBLEM,
				   "Cannot specify `--dst-zone' "
				   "together with `--src-zone'\n");

		if (strlen(optarg) == 0)
			xtables_error(PARAMETER_PROBLEM,
			           "`--dst-zone' must be accompanied by "
				   "a zone name\n");

		strncpy((char *)info->name, optarg, sizeof(info->name));
		info->name[IPT_ZONE_NAME_LENGTH] = '\0';

		*flags |= F_DST;
		break;

	case '3':
		if (*flags & F_CHILDREN)
			xtables_error(PARAMETER_PROBLEM,
			           "Cannot specify `--children' "
				   "more than once\n");

		info->flags |= IPT_ZONE_CHILDREN;

		*flags |= F_CHILDREN;
		break;

	case '4':
		if (*flags & F_UMBRELLA)
			xtables_error(PARAMETER_PROBLEM,
			           "Cannot specify `--umbrella' "
				   "more than once\n");

		info->flags |= IPT_ZONE_UMBRELLA;

		*flags |= F_UMBRELLA;
		break;

	default:
		return 0;
	}

	return 1;
}

static int
zone_parse_v1(int c, char **argv, int invert, unsigned int *flags,
	      const void *entry, struct xt_entry_match **match)
{
	struct ipt_zone_info_v1 *info = (struct ipt_zone_info_v1 *) (*match)->data;

	switch (c)
	{
	case '1': /* src-zone */
		if (*flags & F_SRC)
			xtables_error(PARAMETER_PROBLEM,
				   "Cannot specify `--source-zones' "
				   "more than once\n");
		if (*flags & F_DST)
			xtables_error(PARAMETER_PROBLEM,
				   "Cannot specify `--source-zones' "
				   "together with `--destination-zones'\n");

		if (strlen(optarg) == 0)
			xtables_error(PARAMETER_PROBLEM,
				   "`--source-zones' must be accompanied "
				   "by a zone name\n");

		info->count = parse_zone_names(optarg,
		                               info,
					       sizeof(info->names[0]) - 1);
		info->flags |= IPT_ZONE_SRC;

		*flags |= F_SRC;
		break;

	case '2': /* dst-zone */
		if (*flags & F_DST)
			xtables_error(PARAMETER_PROBLEM,
				   "Cannot specify `--destination-zones' "
				   "more than once\n");
		if (*flags & F_SRC)
			xtables_error(PARAMETER_PROBLEM,
				   "Cannot specify `--destination-zones' "
				   "together with `--source-zones'\n");

		if (strlen(optarg) == 0)
			xtables_error(PARAMETER_PROBLEM,
				   "`--destination-zones' must be accompanied "
				   "by a zone name\n");

		info->count = parse_zone_names(optarg,
					       info,
					       sizeof(info->names[0]) - 1);

		*flags |= F_DST;
		break;

	case '3':
		if (*flags & F_CHILDREN)
			xtables_error(PARAMETER_PROBLEM,
			           "Cannot specify `--children' "
				   "more than once\n");

		info->flags |= IPT_ZONE_CHILDREN;

		*flags |= F_CHILDREN;
		break;

	case '4':
		if (*flags & F_UMBRELLA)
			xtables_error(PARAMETER_PROBLEM,
			           "Cannot specify `--umbrella' "
				   "more than once\n");

		info->flags |= IPT_ZONE_UMBRELLA;

		*flags |= F_UMBRELLA;
		break;

	default:
		return 0;
	}

	return 1;
}

static void
zone_final_check(unsigned int flags)
{
	if (!(flags & (F_SRC | F_DST)))
		xtables_error(PARAMETER_PROBLEM,
		           "You must specify either `--src-zone' "
			   "or `--dst-zone'\n");
	if ((flags & F_UMBRELLA) && !(flags & F_CHILDREN))
		xtables_error(PARAMETER_PROBLEM,
		           "Cannot specify `--umbrella' "
			   "without `--children'\n");
}

static void
zone_print_v0(const void *ip, const struct xt_entry_match *match, int numeric)
{
	struct ipt_zone_info *info = (struct ipt_zone_info *) match->data;

	if (info->flags & IPT_ZONE_SRC)
		fputs("source", stdout);
	else
		fputs("destination", stdout);
	printf(" zone \"%s\" ", info->name);

	if (info->flags & IPT_ZONE_CHILDREN)
		fputs("children ", stdout);

	if (info->flags & IPT_ZONE_UMBRELLA)
		fputs("umbrella ", stdout);
}

static void
zone_print_v1(const void *ip, const struct xt_entry_match *match, int numeric)
{
	struct ipt_zone_info_v1 *info = (struct ipt_zone_info_v1 *) match->data;
	int i;

	if (info->flags & IPT_ZONE_SRC)
		fputs("source", stdout);
	else
		fputs("destination", stdout);
	printf(" zones \"");

	for (i = 0; i!=info->count; ++i)
		printf ("%s%s", i ? "," : "", info->names[i]);

	printf("\" ");

	if (info->flags & IPT_ZONE_CHILDREN)
		fputs("children ", stdout);

	if (info->flags & IPT_ZONE_UMBRELLA)
		fputs("umbrella ", stdout);
}

static void
zone_save_v0(const void *ip, const struct xt_entry_match *match)
{
	struct ipt_zone_info *info = (struct ipt_zone_info *) match->data;

	if (info->flags & IPT_ZONE_SRC)
		fputs("--src-zone ", stdout);
	else
		fputs("--dst-zone ", stdout);
	printf("\"%s\" ", info->name);

	if (info->flags & IPT_ZONE_CHILDREN)
		fputs("--children ", stdout);

	if (info->flags & IPT_ZONE_UMBRELLA)
		fputs("--umbrella ", stdout);
}

static void
zone_save_v1(const void *ip, const struct xt_entry_match *match)
{
	struct ipt_zone_info_v1 *info = (struct ipt_zone_info_v1 *) match->data;
	int i;

	if (info->flags & IPT_ZONE_SRC)
		fputs("--szones ", stdout);
	else
		fputs("--dzones ", stdout);

	printf("\"");
	for (i = 0; i!=info->count; ++i)
		printf ("%s%s", i ? "," : "", info->names[i]);
	printf("\" ");

	if (info->flags & IPT_ZONE_CHILDREN)
		fputs("--children ", stdout);

	if (info->flags & IPT_ZONE_UMBRELLA)
		fputs("--umbrella ", stdout);
}

static struct xtables_match zone_match_v0 = {
	.name		= "zone",
	.family		= NFPROTO_IPV4,
	.version	= XTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct ipt_zone_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct ipt_zone_info)),
	.help		= zone_help_v0,
	.parse		= zone_parse_v0,
	.final_check	= zone_final_check,
	.print		= zone_print_v0,
	.save		= zone_save_v0,
	.extra_opts	= zone_opts_v0,
};

static struct xtables_match zone_match_v1 = {
	.name		= "zone",
	.family		= NFPROTO_UNSPEC,
	.revision	= 1,
	.version	= XTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct ipt_zone_info_v1)),
	.userspacesize	= XT_ALIGN(sizeof(struct ipt_zone_info_v1)),
	.help		= zone_help_v1,
	.parse		= zone_parse_v1,
	.final_check	= zone_final_check,
	.print		= zone_print_v1,
	.save		= zone_save_v1,
	.extra_opts	= zone_opts_v1,
};

void _init(void)
{
	xtables_register_match(&zone_match_v0);
	xtables_register_match(&zone_match_v1);
}
