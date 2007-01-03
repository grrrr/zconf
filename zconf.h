/* 
zconf - zeroconf networking objects

Copyright (c)2006 Thomas Grill (gr@grrrr.org)
For information on usage and redistribution, and for a DISCLAIMER OF ALL
WARRANTIES, see the file, "license.txt," in this distribution.  
*/

#ifndef __ZCONF_H
#define __ZCONF_H

#define FLEXT_ATTRIBUTES 1

#include <flext.h>

#if FLEXT_OS == FLEXT_OS_WIN
	#include <stdlib.h>
    #include <winsock2.h>
#else
	#include <unistd.h>
	#include <netdb.h>
	#include <sys/types.h>
	#include <sys/socket.h>
	#include <net/if.h>
#endif

#include <dns_sd.h>

#include <vector>
#include <string>

namespace zconf {

#define MAX_DOMAIN_LABEL 63
#define MAX_DOMAIN_NAME 255

typedef const t_symbol *Symbol;

std::string DNSEscape(const char *txt,bool escdot = true);
std::string DNSUnescape(const char *txt);

class Worker
	: public flext
{
	friend class Base;
	friend void Free(Worker *w);

protected:
	Worker(Base *b): self(b),client(0),fd(-1) {}
	virtual ~Worker();
	
	inline void Stop();
	
	// to be called from idle function (does the actual work)
	virtual bool Init();	
	
	Base *self;
	DNSServiceRef client;
	int fd;


	typedef struct { unsigned char c[ 64]; } domainlabel;      // One label: length byte and up to 63 characters.
	typedef struct { unsigned char c[256]; } domainname;       // Up to 255 bytes of length-prefixed domainlabels.

	static char *conv_label2str(const domainlabel *label, char *ptr);
	static char *conv_domain2str(const domainname *name, char *ptr);
	static bool conv_type_domain(const void *rdata, uint16_t rdlen, char *type, char *domain);
};

class Base
	: public flext_base
{
	FLEXT_HEADER_S(Base,flext_base,Setup)

	friend class Worker;

public:
	Base();
	virtual ~Base();
	
    virtual void OnError(DNSServiceErrorType error);

protected:
	void Install(Worker *w);

	void Stop()
	{
		if(worker) {
			worker->self = NULL; // mark as abandoned
			worker = NULL;
		}
	}

	static Symbol sym_error,sym_add,sym_remove;

private:
	Worker *worker;

	typedef std::vector<Worker *> Workers;
	static Workers *workers;

	static t_int idlefun(t_int *data);

	static void Setup(t_classid);
};

inline void Worker::Stop() { if(self) self->Stop(); }

}

#endif
