#include "test.h"

int inet_pton(int af, const char *src, void *dst);
const char *inet_ntop(int af, const void *src, char *dst, size_t size);

static struct in6_addr *
string_as_address_v6(const char *src)
{
  static struct in6_addr _buf;

  g_assert(inet_pton(AF_INET6, src, &_buf));

  return &_buf;
}

static const char *
address_as_string(const struct in6_addr *addr)
{
  static char _buf[256];

  g_assert(inet_ntop(AF_INET6, addr, _buf, sizeof(_buf)));

  return _buf;
}

static void
__print_node(GString *str, int level, const struct kz_lookup_ipv6_node *node)
{
  if (node->zone)
    g_string_append_printf(str, "%*d|%s/%d -> '%s'\n", 2 * level, level, address_as_string(&node->addr), node->prefix_len, (char *)node->zone);
  else
    g_string_append_printf(str, "%*d|%s/%d\n", 2 * level, level, address_as_string(&node->addr), node->prefix_len);
}

static void
__print_tree(GString *str, int level, const struct kz_lookup_ipv6_node *node)
{
  if (node == NULL)
    return;
  __print_node(str, level, node);
  __print_tree(str, level + 1, node->left);
  __print_tree(str, level + 1, node->right);
}

static const char *
tree_as_string(const struct kz_lookup_ipv6_node *root){

  static GString *_str = NULL;

  if (_str == NULL) {
    _str = g_string_new("");
  }

  g_string_assign(_str, "");
  __print_tree(_str, 0, root);

  return _str->str;
}

#define TREE_NEW(root) do { if (root) ipv6_destroy(root); root = ipv6_node_new(); } while (0);
#define TREE_ADD(root, net, prefix) ipv6_add(root, string_as_address_v6(net), prefix)
#define TREE_ADD_DATA(root, net, prefix, data)        \
  do {                \
    struct kz_lookup_ipv6_node *n = ipv6_add(root, string_as_address_v6(net), prefix); \
    if (n)              \
      n->zone= (struct kz_zone *) data;   \
  } while (0);
#define TREE_PRINT(root) printf("%s", tree_as_string(root))
#define TREE_CHECK(root, str) do { if (g_test_verbose()) TREE_PRINT(root);\
    g_assert_cmpstr(tree_as_string(root), ==, str); } while (0);
#define TREE_LOOKUP(root, address, expected)        \
  do {                \
    struct kz_lookup_ipv6_node *n = ipv6_lookup(root, string_as_address_v6(address)); \
    g_assert(n != NULL);          \
    g_assert_cmpstr((char *)n->zone, ==, expected);   \
  } while (0);
#define TREE_LOOKUP_FAILS(root, address)        \
  do {                \
    struct kz_lookup_ipv6_node *n = ipv6_lookup(root, string_as_address_v6(address)); \
    g_assert(n == NULL || n->zone == NULL);     \
  } while (0);

static void
test_print(void)
{
  struct kz_lookup_ipv6_node *root = ipv6_node_new();

  TREE_CHECK(root,
       "0|::/0\n");

  TREE_ADD(root, "::", 32);
  TREE_ADD(root, "::", 64);
  TREE_ADD(root, "ffff::", 16);
  TREE_ADD(root, "ffff:ff00::", 32);
  TREE_ADD(root, "ffff:f000::", 32);
  TREE_CHECK(root,
       "0|::/0\n"
       " 1|::/32\n"
       "   2|::/64\n"
       " 1|ffff::/16\n"
       "   2|ffff:f000::/20\n"
       "     3|ffff:f000::/32\n"
       "     3|ffff:ff00::/32\n");

  ipv6_destroy(root);
}

static void
test_add(void)
{
  struct kz_lookup_ipv6_node *root = NULL;

  /* construct an empty tree */
  TREE_NEW(root);
  TREE_CHECK(root,
       "0|::/0\n");

  /* postfix insertion */
  TREE_ADD(root, "ffff::", 15);
  TREE_ADD(root, "ffff:ffff::", 31);
  TREE_CHECK(root,
       "0|::/0\n"
       " 1|ffff::/15\n"
       "   2|ffff:ffff::/31\n");

  TREE_NEW(root);
  TREE_ADD(root, "::", 15);
  TREE_ADD(root, "::", 31);
  TREE_CHECK(root,
       "0|::/0\n"
       " 1|::/15\n"
       "   2|::/31\n");

  /* inserting shorter prefix */
  TREE_NEW(root);
  TREE_ADD(root, "ffff:ffff::", 31);
  TREE_ADD(root, "ffff::", 15);
  TREE_CHECK(root,
       "0|::/0\n"
       " 1|ffff::/15\n"
       "   2|ffff:ffff::/31\n");

  TREE_NEW(root);
  TREE_ADD(root, "::", 31);
  TREE_ADD(root, "::", 15);
  TREE_CHECK(root,
       "0|::/0\n"
       " 1|::/15\n"
       "   2|::/31\n");

  /* same prefix length, but different prefix */
  TREE_NEW(root);
  TREE_ADD(root, "ffff::", 16);
  TREE_ADD(root, "f0ff::", 16);
  TREE_CHECK(root,
       "0|::/0\n"
       " 1|f0ff::/4\n"
       "   2|f0ff::/16\n"
       "   2|ffff::/16\n");

  TREE_NEW(root);
  TREE_ADD(root, "00ff::", 16);
  TREE_ADD(root, "0fff::", 16);
  TREE_CHECK(root,
       "0|::/0\n"
       " 1|fff::/4\n"
       "   2|ff::/16\n"
       "   2|fff::/16\n");

  /* adding a node already present */
  TREE_NEW(root);
  TREE_ADD(root, "fe80::", 10);
  TREE_ADD(root, "fe80::", 10);
  TREE_ADD(root, "fe8f::", 10);
  TREE_CHECK(root,
       "0|::/0\n"
       " 1|fe80::/10\n");

  ipv6_destroy(root);
}

static void
test_lookup(void)
{
  struct kz_lookup_ipv6_node *root = NULL;

  /* empty tree */
  TREE_NEW(root);
  TREE_LOOKUP_FAILS(root, "::1");

  /* add a single subnet */
  TREE_NEW(root);
  TREE_ADD_DATA(root, "fe80::", 10, "link-local");
  TREE_LOOKUP(root, "fe80:1::", "link-local");
  TREE_LOOKUP_FAILS(root, "::1");
  TREE_LOOKUP_FAILS(root, "fe00::");

  /* check best match */
  TREE_NEW(root);
  TREE_ADD_DATA(root, "::f000", 116, "subnet1");
  TREE_LOOKUP(root, "::ffff", "subnet1");
  TREE_ADD_DATA(root, "::f800", 117, "subnet11");
  TREE_LOOKUP(root, "::ffff", "subnet11");
  TREE_ADD_DATA(root, "::f000", 117, "subnet12");
  TREE_LOOKUP(root, "::ffff", "subnet11");
  TREE_LOOKUP(root, "::f0ff", "subnet12");

  /* exact match */
  TREE_ADD_DATA(root, "::ffff", 128, "exact1");
  TREE_LOOKUP(root, "::ffff", "exact1");
  TREE_ADD_DATA(root, "::fffe", 128, "exact2");
  TREE_LOOKUP(root, "::ffff", "exact1");
  TREE_LOOKUP(root, "::fffe", "exact2");
  TREE_LOOKUP(root, "::fff0", "subnet11");

  ipv6_destroy(root);
}

int
main(int argc, char *argv[])
{
  g_test_init(&argc, &argv, NULL);

  g_test_add_func("/radix/print", test_print);
  g_test_add_func("/radix/add", test_add);
  g_test_add_func("/radix/lookup", test_lookup);

  g_test_run();

  return 0;
}
