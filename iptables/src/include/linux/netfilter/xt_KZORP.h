#ifndef _XT_KZORP_H_target
#define _XT_KZORP_H_target

/*
 * KZORP target makes the necessary decision by your policy settings performs
 * redirection, DAC decisions, and forwards services.
 */
struct xt_kzorp_target_info {
	u_int32_t mark_mask;
	u_int32_t mark_value;
	u_int32_t flags;
};

#endif /* _XT_KZORP_H_target */
