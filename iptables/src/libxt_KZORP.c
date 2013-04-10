/*
 * Shared library add-on to iptables to add KZORP target support.
 *
 * Copyright (C) 2011 BalaBit IT Ltd.
 */
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>

#include <xtables.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_KZORP.h>

static const struct option kzorp_tg_opts[] = {
	{ .name = "tproxy-mark", .has_arg = 1, .val = '1'},
	{NULL},
};

enum {
	PARAM_MARK = 1 << 0
};

static void kzorp_tg_help(void)
{
	printf(
"KZORP target options:\n"
"  --tproxy-mark value[/mask]	    Mark redirected packets with the given value/mask\n\n");
}

static void parse_kzorp_mark(char *s, struct xt_kzorp_target_info *info)
{
	unsigned int value, mask = UINT32_MAX;
	char *end;

	if (!xtables_strtoui(s, &end, &value, 0, UINT32_MAX))
		xtables_param_act(XTF_BAD_VALUE, "KZORP", "--tproxy-mark", s);
	if (*end == '/')
		if (!xtables_strtoui(end + 1, &end, &mask, 0, UINT32_MAX))
			xtables_param_act(XTF_BAD_VALUE, "KZORP", "--tproxy-mark", s);
	if (*end != '\0')
		xtables_param_act(XTF_BAD_VALUE, "KZORP", "--tproxy-mark", s);

	info->mark_mask = mask;
	info->mark_value = value;
}

static int kzorp_tg_parse(int c, char **argv, int invert, unsigned int *flags,
			const void *entry, struct xt_entry_target **target)
{
	struct xt_kzorp_target_info *tproxyinfo = (void *)(*target)->data;

	switch (c) {
	case '1':
		xtables_param_act(XTF_ONLY_ONCE, "KZORP", "--tproxy-mark", *flags & PARAM_MARK);
		xtables_param_act(XTF_NO_INVERT, "KZORP", "--tproxy-mark", invert);
		parse_kzorp_mark(optarg, tproxyinfo);
		*flags |= PARAM_MARK;
		return 1;
	}

	return 0;
}

static void kzorp_tg_print(const void *ip, const struct xt_entry_target *target,
			 int numeric)
{
	const struct xt_kzorp_target_info *info = (const void *)target->data;
	printf("KZORP mark 0x%x/0x%x",
	       (unsigned int)info->mark_value,
	       (unsigned int)info->mark_mask);
}

static void kzorp_tg_save(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_kzorp_target_info *info = (const void *)target->data;

	printf("--tproxy-mark 0x%x/0x%x ",
	       (unsigned int)info->mark_value, (unsigned int)info->mark_mask);
}

static struct xtables_target kzorp_tg_reg = {
	.name	         = "KZORP",
	.family	       = NFPROTO_UNSPEC,
	.version       = XTABLES_VERSION,
	.size	         = XT_ALIGN(sizeof(struct xt_kzorp_target_info)),
	.userspacesize = XT_ALIGN(sizeof(struct xt_kzorp_target_info)),
	.help	         = kzorp_tg_help,
	.parse	       = kzorp_tg_parse,
	.print	       = kzorp_tg_print,
	.save	         = kzorp_tg_save,
	.extra_opts    = kzorp_tg_opts,
};

void _init(void)
{
	xtables_register_target(&kzorp_tg_reg);
}
