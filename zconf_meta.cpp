/* 
zconf - zeroconf networking objects

Copyright (c)2006 Thomas Grill (gr@grrrr.org)
For information on usage and redistribution, and for a DISCLAIMER OF ALL
WARRANTIES, see the file, "license.txt," in this distribution.  
*/

#include "zconf.h"

namespace zconf {

#define kServiceMetaQueryName  "_services._dns-sd._udp.local."


class MetaBase
	: public Base
{
public:
    virtual void OnMeta(const char *type,const char *domain,int interf,bool add,bool more) = 0;
};

class MetaWorker
	: public Worker
{
public:
	MetaWorker(MetaBase *s,int i)
		: Worker(s)
		, interf(i)
	{}
	
protected:
	int interf;
	
	virtual bool Init()
	{
		DNSServiceErrorType err = DNSServiceQueryRecord(
			&client,
			0,  // no flags
            interf < 0?kDNSServiceInterfaceIndexLocalOnly:kDNSServiceInterfaceIndexAny, 
			kServiceMetaQueryName,  // meta-query record name
			kDNSServiceType_PTR,  // DNS PTR Record
			kDNSServiceClass_IN,  // Internet Class
			callback, this
		);

		if(LIKELY(err == kDNSServiceErr_NoError)) {
			FLEXT_ASSERT(client);
			return Worker::Init();
		}
		else {
			static_cast<MetaBase *>(self)->OnError(err);
			return false;
		}
	} 
	
private:
	static void DNSSD_API callback(
		DNSServiceRef service, 
		DNSServiceFlags flags, 
		uint32_t interf, 
		DNSServiceErrorType errorCode,
		const char * fullname, 
		uint16_t rrtype, 
		uint16_t rrclass, 
		uint16_t rdlen, 
		const void * rdata, 
		uint32_t ttl, 
		void * context)
	{    
		FLEXT_ASSERT(!strcmp(fullname, kServiceMetaQueryName));
						
        MetaWorker *w = (MetaWorker *)context;
		FLEXT_ASSERT(w->self);

		if(LIKELY(errorCode == kDNSServiceErr_NoError)) {
		    char domain[MAX_DOMAIN_NAME]    = "";
			char type[MAX_DOMAIN_NAME]      = "";
		    /* Get the type and domain from the discovered PTR record. */
			conv_type_domain(rdata, rdlen, type, domain);        

			static_cast<MetaBase *>(w->self)->OnMeta(type,domain,interf,(flags & kDNSServiceFlagsAdd) != 0,(flags & kDNSServiceFlagsMoreComing) != 0);
		} 
		else
			static_cast<MetaBase *>(w->self)->OnError(errorCode);
	}
};

class Meta
	: public MetaBase
{
	FLEXT_HEADER_S(Meta,MetaBase,Setup)
public:

	Meta()
		: active(false),interf(0)
	{
		Update();
	}

	void ms_active(bool a)
	{
		active = a;
		Update();
	}

	void ms_interface(int i)
	{
		if(i != interf) {
			interf = i;
			Update();
		}
	}

protected:
	bool active;
	int interf;

	void Update()
	{
		if(active)
			Install(new MetaWorker(this,interf));
		else
			Stop();
	}

    virtual void OnMeta(const char *type,const char *domain,int interf,bool add,bool more)
    {
        t_atom at[4]; 
		SetString(at[0],type);
		SetString(at[1],domain);
		SetInt(at[2],interf);
        SetBool(at[3],more);
		ToQueueAnything(GetOutAttr(),add?sym_add:sym_remove,4,at);
    }

	FLEXT_ATTRGET_B(active)
	FLEXT_CALLSET_B(ms_active)
	FLEXT_CALLSET_I(ms_interface)
	FLEXT_ATTRGET_I(interf)

	static void Setup(t_classid c)
	{
		FLEXT_CADDATTR_VAR(c,"active",active,ms_active);
		FLEXT_CADDATTR_VAR(c,"interface",interf,ms_interface);
	}
};

FLEXT_LIB("zconf.meta",Meta)

} //namespace

