#include "zconf.h"

#define ZCONF_VERSION "0.0.2"

namespace zconf {

const t_symbol *sym_local;

static void main()
{
	flext::post("----------------------------------");
	flext::post("zconf - zeroconfig objects");
    flext::post("version " ZCONF_VERSION " (c)2006 Thomas Grill");
#ifdef FLEXT_DEBUG
    flext::post("");
    flext::post("DEBUG BUILD - " __DATE__ " " __TIME__);
#endif
	flext::post("----------------------------------");

	sym_local = flext::MakeSymbol("local");

	// call the objects' setup routines
	FLEXT_SETUP(Browse);
	FLEXT_SETUP(Service);
	FLEXT_SETUP(Resolve);
}

}

// setup the library
FLEXT_LIB_SETUP(zconf,zconf::main)

