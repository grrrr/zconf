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
    virtual void OnResolve(const char *hostname,const char *type,const char *domain,int port,const char *ifname,const char *txtRecord) = 0;
};

class ResolveWorker
	: public Worker
{
public:
	ResolveWorker(ResolveBase *s,Symbol n,Symbol t,Symbol d,Symbol i)
		: Worker(s)
		, name(n),type(t),domain(d),interf(i)
	{}
	
protected:
	virtual bool Init()
	{
		uint32_t ifix = interf?conv_str2if(GetString(interf)):kDNSServiceInterfaceIndexAny;

		char hostname[MAX_DOMAIN_NAME+1];
		if(!name) {
			gethostname(hostname,MAX_DOMAIN_NAME);
			char *dot = strchr(hostname,'.');
			if(dot) *dot = 0;  // we want only the host name, no domain
		}

		DNSServiceErrorType err = DNSServiceResolve(
            &client,
			0, // default renaming behaviour 
			ifix,
			name?GetString(name):hostname,
			GetString(type),
			domain?GetString(domain):"local",
			callback, this
		);

		if(LIKELY(err == kDNSServiceErr_NoError)) {
			FLEXT_ASSERT(client);
			return Worker::Init();
		}
		else {
			static_cast<ResolveBase *>(self)->OnError(err);
			return false;
		}
	} 
	
	Symbol name,type,domain,interf;

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
		FLEXT_ASSERT(w->self);

		if(LIKELY(errorCode == kDNSServiceErr_NoError)) {
			union { uint16_t s; unsigned char b[2]; } oport = { opaqueport };
			uint16_t port = ((uint16_t)oport.b[0]) << 8 | oport.b[1];
		
			char ifname[IF_NAMESIZE] = "";
			conv_if2str(ifIndex,ifname);
		
			char temp[256],*t,*t1;
			strcpy(temp,fullname);
			
			t = getdot(t1 = temp);
			FLEXT_ASSERT(t); // after host name
			*t = 0;
			const char *hostname = t1; // host name

			t = getdot(t1 = t+1);
			FLEXT_ASSERT(t); // middle dot in type
			t = getdot(t+1);
			FLEXT_ASSERT(t); // after type
			*t = 0;
			const char *type = t1; // type

			const char *domain = t+1; // domain

			static_cast<ResolveBase *>(w->self)->OnResolve(hostname,type,domain,port,ifname,txtRecord && *txtRecord?txtRecord:NULL);
		}
		else
			static_cast<ResolveBase *>(w->self)->OnError(errorCode);
		
		// remove immediately
		w->Stop();
    }
	
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


class Resolve
	: public ResolveBase
{
	FLEXT_HEADER_S(Resolve,ResolveBase,Setup)
public:

	Resolve() {}

	void m_resolve(int argc,const t_atom *argv)
	{
        if(argc == 0)
            Stop();
        else if(argc < 1 || !IsSymbol(argv[0])) {
			post("%s - %s: type (like _ssh._tcp or _osc._udp) must be given",thisName(),GetString(thisTag()));
		}
        else {
		    Symbol type = GetSymbol(argv[0]);
		    Symbol name = argc >= 3?GetASymbol(argv[1]):NULL;
            Symbol domain = argc >= 3?GetASymbol(argv[2]):NULL;
            Symbol interf = argc >= 4?GetASymbol(argv[3]):NULL;

		    Install(new ResolveWorker(this,name,type,domain,interf));
        }
	}

protected:

	static Symbol sym_resolve;

    virtual void OnResolve(const char *hostname,const char *type,const char *domain,int port,const char *ifname,const char *txtRecord)
    {
		t_atom at[6];
        SetString(at[0],hostname); // host name
        SetString(at[1],type); // type
        SetString(at[2],domain); // domain
		SetInt(at[3],port);
		SetString(at[4],ifname);
		if(txtRecord) SetString(at[5],txtRecord);
		ToOutAnything(GetOutAttr(),sym_resolve,txtRecord?6:5,at);
    }

	FLEXT_CALLBACK_V(m_resolve)

	static void Setup(t_classid c)
	{
		sym_resolve = MakeSymbol("resolve");
	
		FLEXT_CADDMETHOD_(c,0,sym_resolve,m_resolve);
	}
};

Symbol Resolve::sym_resolve;

FLEXT_LIB("zconf.resolve",Resolve)

} // namespace
