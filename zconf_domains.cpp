/* 
zconf - zeroconf networking objects

Copyright (c)2006 Thomas Grill (gr@grrrr.org)
For information on usage and redistribution, and for a DISCLAIMER OF ALL
WARRANTIES, see the file, "license.txt," in this distribution.  
*/

#include "zconf.h"

namespace zconf {

class DomainsBase
	: public Base
{
public:
    virtual void OnDomain(const char *domain,const char *ifname,bool add) = 0;
};

class DomainsWorker
	: public Worker
{
public:
	DomainsWorker(DomainsBase *s,Symbol i,bool reg)
		: Worker(s)
        , interf(i),regdomains(reg)
	{}
	
protected:
	Symbol interf;
    bool regdomains;

	virtual bool Init()
	{
		uint32_t ifix = interf?conv_str2if(GetString(interf)):kDNSServiceInterfaceIndexAny;

        DNSServiceErrorType err = DNSServiceEnumerateDomains( 
            &client, 
            regdomains?kDNSServiceFlagsRegistrationDomains:kDNSServiceFlagsBrowseDomains, // flags
            ifix,
            &callback, this
        );

		if(LIKELY(err == kDNSServiceErr_NoError)) {
			FLEXT_ASSERT(client);
			return Worker::Init();
		}
		else {
			static_cast<DomainsBase *>(self)->OnError(err);
			return false;
		}
	} 
	
private:

    static void DNSSD_API callback(
        DNSServiceRef client, 
        DNSServiceFlags flags, // kDNSServiceFlagsMoreComing + kDNSServiceFlagsAdd
        uint32_t ifIndex, 
        DNSServiceErrorType errorCode,
        const char *replyDomain,                             
        void *context)
    {
        DomainsWorker *w = (DomainsWorker *)context;
		FLEXT_ASSERT(w->self);
		if(LIKELY(errorCode == kDNSServiceErr_NoError)) {
			char ifname[IF_NAMESIZE] = "";
			conv_if2str(ifIndex,ifname);
			static_cast<DomainsBase *>(w->self)->OnDomain(replyDomain,ifname,(flags & kDNSServiceFlagsAdd) != 0);
		}
		else
			static_cast<DomainsBase *>(w->self)->OnError(errorCode);
    }

};

class Domains
	: public DomainsBase
{
	FLEXT_HEADER_S(Domains,DomainsBase,Setup)
public:

	Domains()
        : mode(0),interf(NULL)
	{		
		Update();
	}

    void ms_mode(int m) 
    {
        if(m < 0 || m > 2)
            post("%s - mode must be 0 (off), 1 (browse domains), 2 (registration domains)",thisName());
        else {
            mode = m;
            Update();
        }
    }

	void ms_interface(const AtomList &args)
	{
		Symbol i;
		if(!args.Count())
			i = NULL;
		if(args.Count() == 1 && IsSymbol(args[0]))
			i = GetSymbol(args[0]);
		else {
			post("%s - interface [symbol]",thisName());
			return;
		}

		if(i != interf) {
			interf = i;
			Update();
		}
	}

	void mg_interface(AtomList &args) const 
	{ 
		if(interf) { 
			args(1); 
			SetSymbol(args[0],interf); 
		} 
	}

protected:
    int mode;
	Symbol interf;

	void Update()
	{
        if(mode)
            Install(new DomainsWorker(this,interf,mode == 2));
        else
            Stop();
	}

    virtual void OnDomain(const char *domain,const char *ifname,bool add)
    {
        t_atom at[2]; 
		SetString(at[0],domain);
		SetString(at[1],ifname);
		ToOutAnything(GetOutAttr(),add?sym_add:sym_remove,2,at);
    }

    FLEXT_ATTRGET_I(mode)
    FLEXT_CALLSET_I(ms_mode)
	FLEXT_CALLVAR_V(mg_interface,ms_interface)

	static void Setup(t_classid c)
	{
        FLEXT_CADDATTR_VAR(c,"mode",mode,ms_mode);
        FLEXT_CADDATTR_VAR(c,"interface",mg_interface,ms_interface);
	}
};

FLEXT_LIB("zconf.domains",Domains)

} //namespace
