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
    virtual void OnDomain(const char *domain,bool add) = 0;
};

class DomainsWorker
	: public Worker
{
public:
	DomainsWorker(DomainsBase *s,bool reg)
		: Worker(s)
        , regdomains(reg)
	{}
	
protected:
    bool regdomains;

	virtual bool Init()
	{
        DNSServiceErrorType err = DNSServiceEnumerateDomains( 
            &client, 
            regdomains?kDNSServiceFlagsRegistrationDomains:kDNSServiceFlagsBrowseDomains, // flags
            kDNSServiceInterfaceIndexAny, // kDNSServiceInterfaceIndexLocalOnly or indexed interface
            &callback, this
        );

		if(UNLIKELY(!client || err != kDNSServiceErr_NoError)) {
			post("DNSService call failed: %i",err);
			return false;
		}
		else
			return Worker::Init();
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
		static_cast<DomainsBase *>(w->self)->OnDomain(replyDomain,(flags & kDNSServiceFlagsAdd) != 0);
    }

};

class Domains
	: public DomainsBase
{
	FLEXT_HEADER_S(Domains,DomainsBase,Setup)
public:

	Domains()
        : mode(0)
	{
		AddInAnything("messages");
		AddOutAnything("added/removed service");
		
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

protected:
    int mode;

	static const t_symbol *sym_add,*sym_remove;

	void Update()
	{
        if(mode)
            Install(new DomainsWorker(this,mode == 2));
        else
            Stop();
	}

    virtual void OnDomain(const char *domain,bool add)
    {
        t_atom at; 
		SetString(at,domain);
		ToOutAnything(0,add?sym_add:sym_remove,1,&at);
    }

    FLEXT_ATTRGET_I(mode)
    FLEXT_CALLSET_I(ms_mode)

	static void Setup(t_classid c)
	{
		sym_add = MakeSymbol("add");
		sym_remove = MakeSymbol("remove");

        FLEXT_CADDATTR_VAR(c,"mode",mode,ms_mode);
	}
};

const t_symbol *Domains::sym_add,*Domains::sym_remove;

FLEXT_LIB("zconf.domains",Domains)

} //namespace
