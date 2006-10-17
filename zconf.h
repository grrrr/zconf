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

#include <dns_sd.h>
#if FLEXT_OS == FLEXT_OS_WIN
#include <stdlib.h>
#else
#include <unistd.h>
#endif

#include <vector>

namespace zconf {

typedef const t_symbol *Symbol;

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
};

class Base
	: public flext_base
{
	FLEXT_HEADER_S(Base,flext_base,Setup)

	friend class Worker;

public:
	Base(): worker(NULL) {}
	virtual ~Base();
	
protected:
	void Install(Worker *w)
	{
		if(worker) Stop();
		FLEXT_ASSERT(workers);
		workers->push_back(worker = w);
		// wake up idle....
	}

	void Stop()
	{
		if(worker) {
			worker->self = NULL; // mark as abandoned
			worker = NULL;
		}
	}


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
