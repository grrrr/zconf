/* 
zconf - zeroconf networking objects

Copyright (c)2006 Thomas Grill (gr@grrrr.org)
For information on usage and redistribution, and for a DISCLAIMER OF ALL
WARRANTIES, see the file, "license.txt," in this distribution.  
*/

#include "zconf.h"

#define ZCONF_VERSION "0.0.3"

namespace zconf {

////////////////////////////////////////////////

Worker::~Worker()
{
	FLEXT_ASSERT(!self);
	if(client) 
		DNSServiceRefDeallocate(client);
}

bool Worker::Init()
{
	fd = DNSServiceRefSockFD(client);
	return fd >= 0;
}


////////////////////////////////////////////////

Base::Workers *Base::workers = NULL;

Base::~Base() 
{
	Stop();
}

t_int Base::idlefun(t_int *)
{
	fd_set readfds;
	int maxfds = -1;
	bool init = false;
	FD_ZERO(&readfds);

	FLEXT_ASSERT(workers);
	for(Workers::iterator it = workers->begin(); it != workers->end(); ++it) {
		Worker *w = *it;
		if(!w->client) {
			if(w->Init())
				init = true;
			else
				w->Stop(); // marked to be unused
		}
		else {
			FD_SET(w->fd,&readfds);
			if(w->fd > maxfds) maxfds = w->fd;
		}
	}
	
	if(maxfds >= 0) {
		timeval tv; 
		tv.tv_sec = tv.tv_usec = 0; // don't block
		int result = select(maxfds+1,&readfds,NULL,NULL,&tv);
		if(result > 0) {
			for(Workers::iterator it = workers->begin(); it != workers->end(); ++it) {
				Worker *w = *it;
				if(FD_ISSET(w->fd,&readfds)) {
					DNSServiceErrorType err = DNSServiceProcessResult(w->client);
					if(UNLIKELY(err)) {
						post("DNSServiceProcessResult call failed: %i",err);
						w->Stop();
					}
				}
			}
		}		
	}

	for(int i = workers->size()-1; i >= 0; --i) {
		Worker *w = (*workers)[i];
		if(!w->self) {
			delete w;
			workers->erase(workers->begin()+i);
		}
	}
	
	return init?1:2;
}

void Base::Setup(t_classid)
{
	if(!workers) {
		workers = new Workers;
		sys_callback(idlefun,NULL,0);
	}
}

////////////////////////////////////////////////

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

	// call the objects' setup routines
	FLEXT_SETUP(Browse);
	FLEXT_SETUP(Service);
	FLEXT_SETUP(Resolve);
}

} // namespace

// setup the library
FLEXT_LIB_SETUP(zconf,zconf::main)

