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
    virtual void OnMeta(const char *type,const char *domain,const char *interface,bool add) = 0;
};

class MetaWorker
	: public Worker
{
public:
	MetaWorker(MetaBase *s,Symbol i)
		: Worker(s)
		, interf(i)
	{}
	
protected:
	Symbol interf;
	
	virtual bool Init()
	{
		uint32_t ifix = interf?conv_str2if(GetString(interf)):kDNSServiceInterfaceIndexAny;

		DNSServiceErrorType err = DNSServiceQueryRecord(
			&client,
			0,  // no flags
			ifix,
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
	static void callback(
		DNSServiceRef service, 
		DNSServiceFlags flags, 
		uint32_t interface, 
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
		
			char ifname[IF_NAMESIZE] = "";
			char domain[MAX_DOMAIN_NAME]    = "";
			char type[MAX_DOMAIN_NAME]      = "";
		
			/* Get the type and domain from the discovered PTR record. */
			conv_type_domain(rdata, rdlen, type, domain);        

			/* Convert an interface index into a BSD-style interface name. */
			conv_if2str(interface, ifname);

			static_cast<MetaBase *>(w->self)->OnMeta(type,domain,ifname,(flags & kDNSServiceFlagsAdd) != 0);
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
		: active(false),interf(NULL)
	{
		Update();
	}

	void ms_active(bool a)
	{
		active = a;
		Update();
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
	bool active;
	Symbol interf;

	void Update()
	{
		if(active)
			Install(new MetaWorker(this,interf));
		else
			Stop();
	}

    virtual void OnMeta(const char *type,const char *domain,const char *interface,bool add)
    {
        t_atom at[3]; 
		SetString(at[0],type);
		SetString(at[1],domain);
		SetString(at[2],interface);
		ToOutAnything(GetOutAttr(),add?sym_add:sym_remove,3,at);
    }

	FLEXT_ATTRGET_B(active)
	FLEXT_CALLSET_B(ms_active)
	FLEXT_CALLVAR_V(mg_interface,ms_interface)

	static void Setup(t_classid c)
	{
		FLEXT_CADDATTR_VAR(c,"active",active,ms_active);
		FLEXT_CADDATTR_VAR(c,"interface",mg_interface,ms_interface);
	}
};

FLEXT_LIB("zconf.meta",Meta)

} //namespace

