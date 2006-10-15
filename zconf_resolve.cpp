/* 
zconf - zeroconf networking objects

Copyright (c)2006 Thomas Grill (gr@grrrr.org)
For information on usage and redistribution, and for a DISCLAIMER OF ALL
WARRANTIES, see the file, "license.txt," in this distribution.  
*/

#include "zconf.h"

namespace zconf {

class ResolveBase
	: public Base
{
public:
    virtual void OnResolve(const char *fullName,const char *hostTarget,int port,const char *txtRecord) = 0;
};

class ResolveWorker
	: public Worker
{
public:
	ResolveWorker(ResolveBase *s,const t_symbol *n,const t_symbol *t,const t_symbol *d)
		: Worker(s)
		, name(n),type(t),domain(d)
	{}
	
protected:
	virtual bool Init()
	{
			DNSServiceFlags flags	= 0;		// default renaming behaviour 
			uint32_t interfaceIndex = kDNSServiceInterfaceIndexAny;		// all interfaces 
			DNSServiceErrorType err;
			err = DNSServiceResolve(&client,
									flags,
									interfaceIndex,
									name?GetString(name):NULL,
									GetString(type),
									domain?GetString(domain):NULL,
									callback, this
			);

		if(UNLIKELY(!client || err != kDNSServiceErr_NoError)) {
			post("DNSService call failed: %i",err);
			return false;
		}
		else
			return Worker::Init();
	} 
	
	const t_symbol *name,*type,*domain;

private:
    static void DNSSD_API callback(DNSServiceRef client, 
                                        const DNSServiceFlags flags, 
                                        uint32_t ifIndex, 
                                        DNSServiceErrorType errorCode,
	                                    const char *fullname, 
                                        const char *hosttarget, 
                                        uint16_t port, //opaqueport, 
                                        uint16_t txtLen, 
                                        const char *txtRecord, 
                                        void *context)
	{
        ResolveWorker *w = (ResolveWorker *)context;

//    	union { uint16_t s; unsigned char b[2]; } port = { opaqueport };
//	    uint16_t port = ((uint16_t)port.b[0]) << 8 | port.b[1];

		FLEXT_ASSERT(w->self);
		static_cast<ResolveBase *>(w->self)->OnResolve(fullname,hosttarget,port,txtRecord);
		// remove immediately
		w->Stop();
    }
};


class Resolve
	: public ResolveBase
{
	FLEXT_HEADER_S(Resolve,ResolveBase,Setup)
public:

	Resolve()
	{
		AddInAnything("messages");
		AddOutAnything("resolved host and port for service name");
	}

	void m_resolve(int argc,const t_atom *argv)
	{
		if(argc < 1 || !IsSymbol(argv[0])) {
			post("%s - %s: type (like _ssh._tcp or _osc._udp) must be given at least",thisName(),GetString(thisTag()));
			return;
		}
		
		const t_symbol *type = GetSymbol(argv[0]);
		const t_symbol *name = argc >= 2?GetASymbol(argv[1]):NULL;
		const t_symbol *domain = argc >= 3?GetASymbol(argv[2]):NULL;

		Install(new ResolveWorker(this,name,type,domain));
	}

protected:

    virtual void OnResolve(const char *fullName,const char *hostTarget,int port,const char *txtRecord)
    {
		t_atom at[4];
		SetString(at[0],fullName);
		SetString(at[1],hostTarget);
		SetInt(at[2],port);
		bool txt = txtRecord && *txtRecord;
		if(txt) SetString(at[3],txtRecord);
		ToOutList(0,txt?4:3,at);
    }

	FLEXT_CALLBACK_V(m_resolve)

	static void Setup(t_classid c)
	{
		FLEXT_CADDMETHOD(c,0,m_resolve);
	}
};

FLEXT_LIB("zconf.resolve",Resolve)

} // namespace
