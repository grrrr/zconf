/* 
zconf - zeroconf networking objects

Copyright (c)2006 Thomas Grill (gr@grrrr.org)
For information on usage and redistribution, and for a DISCLAIMER OF ALL
WARRANTIES, see the file, "license.txt," in this distribution.  
*/

#include "zconf.h"

namespace zconf {

class BrowseBase
	: public Base
{
public:
    virtual void OnBrowse(const char *name,const char *type,const char *domain,int ifix,bool add) = 0;
};

class BrowseWorker
	: public Worker
{
public:
	BrowseWorker(BrowseBase *s,Symbol t,Symbol d,int i)
		: Worker(s)
		, type(t),domain(d),interf(i)
	{}
	
protected:
	virtual bool Init()
	{
		DNSServiceErrorType err = DNSServiceBrowse(
            &client, 
			0, // default renaming behaviour
            interf < 0?kDNSServiceInterfaceIndexLocalOnly:kDNSServiceInterfaceIndexAny, 
			GetString(type), 
			domain?GetString(domain):NULL, 
			&callback, this
        );

		if(LIKELY(err == kDNSServiceErr_NoError)) {
			FLEXT_ASSERT(client);
			return Worker::Init();
		}
		else {
			static_cast<BrowseBase *>(self)->OnError(err);
			return false;
		}
	} 
	
	Symbol type,domain;
    int interf;

private:
    static void DNSSD_API callback(
        DNSServiceRef client, 
        DNSServiceFlags flags, // kDNSServiceFlagsMoreComing + kDNSServiceFlagsAdd
        uint32_t ifIndex, 
        DNSServiceErrorType errorCode,
        const char *replyName, 
        const char *replyType, 
        const char *replyDomain,                             
        void *context)
    {
        BrowseWorker *w = (BrowseWorker *)context;
		FLEXT_ASSERT(w->self);
		
		if(LIKELY(errorCode == kDNSServiceErr_NoError))
			static_cast<BrowseBase *>(w->self)->OnBrowse(replyName,replyType,replyDomain,ifIndex,(flags & kDNSServiceFlagsAdd) != 0);
		else
			static_cast<BrowseBase *>(w->self)->OnError(errorCode);
    }

};

class Browse
	: public BrowseBase
{
	FLEXT_HEADER_S(Browse,BrowseBase,Setup)
public:

	Browse(int argc,const t_atom *argv)
		: type(NULL),domain(NULL),interf(0)
	{
		if(argc >= 1) {
			if(IsSymbol(*argv)) 
				type = GetSymbol(*argv);
			else
				throw "type must be a symbol";
			--argc,++argv;
		}
		if(argc >= 1) {
			if(IsSymbol(*argv)) 
				domain = GetSymbol(*argv);
			else
				throw "domain must be a symbol";
			--argc,++argv;
		}
		if(argc >= 1) {
			if(CanbeInt(*argv)) 
				interf = GetAInt(*argv);
			else
				throw "interface must be an int";
			--argc,++argv;
		}
		Update();
	}

	void ms_type(const AtomList &args)
	{
		Symbol t;
		if(!args.Count())
			t = NULL;
		else if(args.Count() == 1 && IsSymbol(args[0]))
			t = GetSymbol(args[0]);
		else {
			post("%s - type [symbol]",thisName());
			return;
		}

		if(t != type) {
			type = t;
			Update();
		}
	}

	void mg_type(AtomList &args) const { if(type) { args(1); SetSymbol(args[0],type); } }

	void ms_domain(const AtomList &args)
	{
		Symbol d;
		if(!args.Count())
			d = NULL;
		else if(args.Count() == 1 && IsSymbol(args[0]))
			d = GetSymbol(args[0]);
		else {
			post("%s - domain [symbol]",thisName());
			return;
		}

		if(d != domain) {
			domain = d;
			Update();
		}
	}
	
	void mg_domain(AtomList &args) const { if(domain) { args(1); SetSymbol(args[0],domain); } }

	void ms_interface(int i)
	{
		if(i != interf) {
			interf = i;
			Update();
		}
	}

protected:
	Symbol type,domain;
    int interf;
	
	virtual void Update()
	{
		if(type)
			Install(new BrowseWorker(this,type,domain,interf));
		else
			Stop();
	}

    virtual void OnBrowse(const char *name,const char *type,const char *domain,int ifix,bool add)
    {
        t_atom at[4]; 
		SetString(at[0],name);
		SetString(at[1],type);
		SetString(at[2],domain);
		SetInt(at[3],ifix);
		ToOutAnything(GetOutAttr(),add?sym_add:sym_remove,4,at);
    }

	FLEXT_CALLVAR_V(mg_type,ms_type)
	FLEXT_CALLVAR_V(mg_domain,ms_domain)
	FLEXT_CALLSET_I(ms_interface)
	FLEXT_ATTRGET_I(interf)
	
	static void Setup(t_classid c)
	{
		FLEXT_CADDATTR_VAR(c,"type",mg_type,ms_type);
		FLEXT_CADDATTR_VAR(c,"domain",mg_domain,ms_domain);
		FLEXT_CADDATTR_VAR(c,"interface",interf,ms_interface);
	}
};

FLEXT_LIB_V("zconf.browse",Browse)

} //namespace

