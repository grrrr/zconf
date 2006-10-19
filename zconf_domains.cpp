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
    virtual void OnDomain(const char *domain,int ifix,bool add,bool more) = 0;
};

class DomainsWorker
	: public Worker
{
public:
	DomainsWorker(DomainsBase *s,int i,bool reg)
		: Worker(s)
        , interf(i),regdomains(reg)
	{}
	
protected:
	int interf;
    bool regdomains;

	virtual bool Init()
	{
        DNSServiceErrorType err = DNSServiceEnumerateDomains( 
            &client, 
            regdomains?kDNSServiceFlagsRegistrationDomains:kDNSServiceFlagsBrowseDomains, // flags
            interf < 0?kDNSServiceInterfaceIndexLocalOnly:kDNSServiceInterfaceIndexAny, 
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
		if(LIKELY(errorCode == kDNSServiceErr_NoError))
			static_cast<DomainsBase *>(w->self)->OnDomain(replyDomain,ifIndex,(flags & kDNSServiceFlagsAdd) != 0,(flags & kDNSServiceFlagsMoreComing) != 0);
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
        : mode(0),interf(0)
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

	void ms_interface(int i)
	{
		if(i != interf) {
			interf = i;
			Update();
		}
	}

protected:
    int mode;
	int interf;

	void Update()
	{
        if(mode)
            Install(new DomainsWorker(this,interf,mode == 2));
        else
            Stop();
	}

    virtual void OnDomain(const char *domain,int ifix,bool add,bool more)
    {
        t_atom at[3]; 
		SetString(at[0],domain);
		SetInt(at[1],ifix);
		SetBool(at[2],more);
		ToOutAnything(GetOutAttr(),add?sym_add:sym_remove,3,at);
    }

    FLEXT_ATTRGET_I(mode)
    FLEXT_CALLSET_I(ms_mode)
	FLEXT_CALLSET_I(ms_interface)
	FLEXT_ATTRGET_I(interf)

	static void Setup(t_classid c)
	{
        FLEXT_CADDATTR_VAR(c,"mode",mode,ms_mode);
        FLEXT_CADDATTR_VAR(c,"interface",interf,ms_interface);
	}
};

FLEXT_LIB("zconf.domains",Domains)

} //namespace
