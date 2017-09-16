#ifndef __COMPAT_H__
#define __COMPAT_H__

#define _ALIGN(x) __attribute__ ((aligned(x)))

#define unlikely(expr) (__builtin_expect(!!(expr), 0))
#define likely(expr) (__builtin_expect(!!(expr), 1))

#endif /* __COMPAT_H__ */
