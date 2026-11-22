#ifndef KYBER_EXPORT_H
#define KYBER_EXPORT_H

/*
 * Public symbol visibility / import-export macros.
 *
 *   Build the static library  : define KYBER_STATIC
 *   Build the DLL            : define KYBER_BUILD_DLL (export)
 *   Consume the DLL          : leave both undefined (import)
 */
#if defined(_WIN32) || defined(__CYGWIN__)
#  if defined(KYBER_STATIC)
#    define KYBER_API
#  elif defined(KYBER_BUILD_DLL)
#    define KYBER_API __declspec(dllexport)
#  else
#    define KYBER_API __declspec(dllimport)
#  endif
#else
#  define KYBER_API __attribute__((visibility("default")))
#endif

#endif /* KYBER_EXPORT_H */
