#ifndef KZ_TEST_H
#define KZ_TEST_H

#include <kzorp.h>
#include <kzorp_lookup_internal.h>

// libc:
void *malloc(size_t size);
void *calloc(size_t nmemb, size_t size);
void *realloc(void *ptr, size_t size);
void free(void *ptr);
int printf(const char *format, ...);
void abort(void);
int atoi(const char *nptr);

// glib/gtestutils.h would redefine some types including time.h:
#define _TIME_H
#define __GLIB_H_INSIDE__
#include <glib/gtestutils.h>

#define KZ_ARRAY(STRUCT, NAME, ELEMENTS...) \
  __typeof__(*((STRUCT *)0)->NAME) array[] = { ELEMENTS }

#define KZ_ALLOC_ARRAY(STRUCT, NAME, ELEMENTS...) \
  ({ KZ_ARRAY(STRUCT, NAME, ELEMENTS); memcpy(calloc(1, sizeof(array)), array, sizeof(array)); })

#define KZ_ARRAY_SIZE(STRUCT, NAME, ELEMENTS...) \
  ({ KZ_ARRAY(STRUCT, NAME, ELEMENTS); sizeof(array) / sizeof(*array); })

#define KZ_STRUCT_ENTRY_INITIALIZER(STRUCT, NAME, ELEMENTS...) \
  .num_##NAME = KZ_ARRAY_SIZE(STRUCT, NAME, ELEMENTS), .NAME = KZ_ALLOC_ARRAY(STRUCT, NAME, ELEMENTS)

#define KZ_RULE_ENTRY_INITIALIZER(NAME, ELEMENTS...) \
  KZ_STRUCT_ENTRY_INITIALIZER(struct kz_dispatcher_n_dimension_rule, NAME, ELEMENTS)

extern unsigned kz_zone_index;

// The zone depth starts with 1, see kz_zone_new in kzorp_core.c:
#define KZ_ZONE_ROOT_INITIALIZER \
  { .depth = 1, .index = kz_zone_index++ }

#define KZ_ZONE_INITIALIZER(PARENT) \
  { .admin_parent = &(PARENT), .depth = PARENT.depth + 1, .index = kz_zone_index++ }

#endif /* KZ_TEST_H */
