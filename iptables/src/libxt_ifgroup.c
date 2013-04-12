/*
 * Shared library add-on to iptables to match
 * packets by the incoming interface group.
 *
 * (c) 2006-2009 Balazs Scheidler <bazsi@balabit.hu>,
 * Laszlo Attila Toth <panther@balabit.hu>
 */
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <xtables.h>
#include <linux/netfilter/xt_ifgroup.h>

static void
ifgroup_help(void)
{
	printf(
"ifgroup v%s options:\n"
"  --ifgroup-in  [!] group[/mask]  incoming interface group and its mask\n"
"  --ifgroup-out [!] group[/mask]  outgoing interface group and its mask\n"
"\n", XTABLES_VERSION);
}

static struct option opts[] = {
	{ .name = "ifgroup-in", .has_arg = true, .val = '1'},
	{ .name = "ifgroup-out", .has_arg = true, .val = '2'},
	{ .name = NULL }
};

enum {
	F_MATCH_IN = 1 << 0,
	F_MATCH_OUT = 1 << 1,
};

#define IFGROUP_DEFAULT_MASK 0xffffffffU

static int
ifgroup_parse(int c, char **argv, int invert, unsigned int *flags,
	      const void *entry, struct xt_entry_match **match)
{
	struct xt_ifgroup_info *info =
			 (struct xt_ifgroup_info *) (*match)->data;
	char *end;

	switch (c) {
	case '1':
		if (*flags & F_MATCH_IN)
			xtables_error(PARAMETER_PROBLEM,
			    "ifgroup match: Can't specify --ifgroup-in twice");

		info->in_group = strtoul(optarg, &end, 0);
		info->in_mask = IFGROUP_DEFAULT_MASK;

		if (*end == '/')
			info->in_mask = strtoul(end+1, &end, 0);

		if (*end != '\0' || end == optarg)
			xtables_error(PARAMETER_PROBLEM,
				  "ifgroup match: Bad ifgroup value `%s'", optarg);

		if (invert)
			info->flags |= XT_IFGROUP_INVERT_IN;

		*flags |= F_MATCH_IN;
		info->flags |= XT_IFGROUP_MATCH_IN;
		break;

	case '2':
		if (*flags & F_MATCH_OUT)
			xtables_error(PARAMETER_PROBLEM,
			    "ifgroup match: Can't specify --ifgroup-out twice");

		info->out_group = strtoul(optarg, &end, 0);
		info->out_mask = IFGROUP_DEFAULT_MASK;

		if (*end == '/')
			info->out_mask = strtoul(end+1, &end, 0);

		if (*end != '\0' || end == optarg)
			xtables_error(PARAMETER_PROBLEM,
			    "ifgroup match: Bad ifgroup value `%s'", optarg);

		if (invert)
			info->flags |= XT_IFGROUP_INVERT_OUT;

		*flags |= F_MATCH_OUT;
		info->flags |= XT_IFGROUP_MATCH_OUT;
		break;

	default:
		return 0;
	}

	return 1;
}

static void
ifgroup_final_check(unsigned int flags)
{
	if (!flags)
		xtables_error(PARAMETER_PROBLEM,
		    "You must specify either "
		    "`--ifgroup-in' or `--ifgroup-out'");
}

static void
ifgroup_print_value_in(struct xt_ifgroup_info *info)
{
	printf("0x%x", info->in_group);
	if (info->in_mask != IFGROUP_DEFAULT_MASK)
		printf("/0x%x", info->in_mask);
	printf(" ");
}

static void
ifgroup_print_value_out(struct xt_ifgroup_info *info)
{
	printf("0x%x", info->out_group);
	if (info->out_mask != IFGROUP_DEFAULT_MASK)
		printf("/0x%x", info->out_mask);
	printf(" ");
}

static void
ifgroup_print(const void *ip,
	      const struct xt_entry_match *match,
	      int numeric)
{
	struct xt_ifgroup_info *info =
		(struct xt_ifgroup_info *) match->data;

	printf("ifgroup ");

	if (info->flags & XT_IFGROUP_MATCH_IN) {
		printf("in %s",
		       info->flags & XT_IFGROUP_INVERT_IN ? "! " : "");
		ifgroup_print_value_in(info);
	}
	if (info->flags & XT_IFGROUP_MATCH_OUT) {
		printf("out %s",
		       info->flags & XT_IFGROUP_INVERT_OUT ? "! " : "");
		ifgroup_print_value_out(info);
	}
}

static void
ifgroup_save(const void *ip, const struct xt_entry_match *match)
{
	struct xt_ifgroup_info *info =
		(struct xt_ifgroup_info *) match->data;

	if (info->flags & XT_IFGROUP_MATCH_IN) {
		printf("%s--ifgroup-in ",
		       info->flags & XT_IFGROUP_INVERT_IN ? "! " : "");
		ifgroup_print_value_in(info);
	}
	if (info->flags & XT_IFGROUP_MATCH_OUT) {
		printf("%s--ifgroup-out ",
		       info->flags & XT_IFGROUP_INVERT_OUT ? "! " : "");
		ifgroup_print_value_out(info);
	}
}

static struct xtables_match ifgroup_match = {
	.family		= NFPROTO_IPV4,
	.name		= "ifgroup",
	.version	= XTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_ifgroup_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_ifgroup_info)),
	.help		= ifgroup_help,
	.parse		= ifgroup_parse,
	.final_check	= ifgroup_final_check,
	.print		= ifgroup_print,
	.save		= ifgroup_save,
	.extra_opts	= opts
};

static struct xtables_match ifgroup_match6 = {
	.family		= NFPROTO_IPV6,
	.name		= "ifgroup",
	.version	= XTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_ifgroup_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_ifgroup_info)),
	.help		= ifgroup_help,
	.parse		= ifgroup_parse,
	.final_check	= ifgroup_final_check,
	.print		= ifgroup_print,
	.save		= ifgroup_save,
	.extra_opts	= opts
};

void _init(void)
{
	xtables_register_match(&ifgroup_match);
	xtables_register_match(&ifgroup_match6);
}
