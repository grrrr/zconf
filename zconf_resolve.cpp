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
		DNSServiceErrorType err = DNSServiceResolve(
            &client,
			0, // default renaming behaviour 
			kDNSServiceInterfaceIndexAny, // all interfaces
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
    static void DNSSD_API callback(
        DNSServiceRef client, 
        DNSServiceFlags flags, 
        uint32_t ifIndex, 
        DNSServiceErrorType errorCode,
	    const char *fullname, 
        const char *hosttarget, 
        uint16_t opaqueport, 
        uint16_t txtLen, 
        const char *txtRecord, 
        void *context)
	{
        ResolveWorker *w = (ResolveWorker *)context;

    	union { uint16_t s; unsigned char b[2]; } oport = { opaqueport };
	    uint16_t port = ((uint16_t)oport.b[0]) << 8 | oport.b[1];

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
        if(argc == 0)
            Stop();
        else if(argc < 2 || !IsSymbol(argv[0]) || !IsSymbol(argv[1])) {
			post("%s - %s: type (like _ssh._tcp or _osc._udp) and host name must be given",thisName(),GetString(thisTag()));
		}
        else {
		    const t_symbol *type = GetSymbol(argv[0]);
		    const t_symbol *name = GetSymbol(argv[1]);
            const t_symbol *domain = argc >= 3?GetASymbol(argv[2]):sym_local;

		    Install(new ResolveWorker(this,name,type,domain));
        }
	}

protected:

    static const t_symbol *sym_local;

    virtual void OnResolve(const char *fullName,const char *hostTarget,int port,const char *txtRecord)
    {
		t_atom at[5];
        char temp[256],*t,*t1;
        strcpy(temp,fullName);

        t = getdot(t1 = temp);
        FLEXT_ASSERT(t); // after host name
        *t = 0;
        SetString(at[0],t1); // host name

        t = getdot(t1 = t+1);
        FLEXT_ASSERT(t); // middle dot in type
        t = getdot(t+1);
        FLEXT_ASSERT(t); // after type
        *t = 0;
        SetString(at[1],t1); // type

        SetString(at[2],t+1); // domain

		SetInt(at[3],port);
		bool txt = txtRecord && *txtRecord;
		if(txt) SetString(at[4],txtRecord);
		ToOutList(0,txt?5:4,at);
    }

	FLEXT_CALLBACK_V(m_resolve)

	static void Setup(t_classid c)
	{
        sym_local = MakeSymbol("local");

		FLEXT_CADDMETHOD(c,0,m_resolve);
	}

private:
    static char *getdot(char *txt)
    {
        bool escaped = false;      
        for(char *t = txt; *t; ++t) {
            if(*t == '\\')
                escaped = !escaped;
            else if(*t == '.' && !escaped)
                return t;
        }
        return NULL;
    }
};

const t_symbol *Resolve::sym_local;

FLEXT_LIB("zconf.resolve",Resolve)

} // namespace
