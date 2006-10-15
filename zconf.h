#ifndef __ZCONF_H
#define __ZCONF_H

#define FLEXT_ATTRIBUTES 1

#include <flext.h>

#include <dns_sd.h>

#if FLEXT_OS == FLEXT_OS_WIN
#include <stdlib.h>
#else
#include <unistd.h>
#endif

namespace zconf {
extern const t_symbol *sym_local;
}

#endif
