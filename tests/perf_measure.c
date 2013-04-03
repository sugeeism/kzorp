#include <sys/resource.h>

long long get_user_time()
{
  struct rusage rusage = {};
  getrusage(RUSAGE_SELF, &rusage);
  return rusage.ru_utime.tv_sec * 1000000 + rusage.ru_utime.tv_usec;
}
