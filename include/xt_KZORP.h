#ifndef _XT_KZORP_H_target
#define _XT_KZORP_H_target

/*
* KZORP target makes the necessary decision by your policy settings performs
* redirection, DAC decisions, and forwards services.
*/
struct xt_kzorp_target_info {
	u_int32_t mark_mask; /* same as in xt_tproxy_target_info */
	u_int32_t mark_value; /* same as in xt_tproxy_target_info */
	u_int32_t flags; /*  for future expansion; must be set to 0! */
};

#endif /* _XT_KZORP_H_target */
