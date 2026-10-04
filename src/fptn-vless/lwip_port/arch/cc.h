#pragma once
/* lwIP platform glue (NO_SYS=1). Works with GCC/Clang and MSVC. */
#include <stdio.h>
#include <stdlib.h>

#define LWIP_PLATFORM_DIAG(x) \
  do {                        \
  } while (0)
#define LWIP_PLATFORM_ASSERT(x)                                  \
  do {                                                           \
    fprintf(stderr, "lwIP assert: %s (%s:%d)\n", x, __FILE__, __LINE__); \
    abort();                                                     \
  } while (0)
#define LWIP_RAND() ((u32_t)rand())

#if defined(_MSC_VER)
#define PACK_STRUCT_BEGIN __pragma(pack(push, 1))
#define PACK_STRUCT_END __pragma(pack(pop))
#define PACK_STRUCT_STRUCT
#define PACK_STRUCT_FIELD(x) x
#endif
