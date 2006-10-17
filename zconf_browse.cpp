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
    virtual void OnBrowse(const char *name,const char *type,const char *domain,bool add) = 0;
};

class BrowseWorker
	: public Worker
{
public:
	BrowseWorker(BrowseBase *s,const t_symbol *t,const t_symbol *d)
		: Worker(s)
		, type(t),domain(d)
	{}
	
protected:
	virtual bool Init()
	{
		DNSServiceFlags flags	= 0;		// default renaming behaviour 
		uint32_t interfaceIndex = kDNSServiceInterfaceIndexAny;		// all interfaces 
							// kDNSServiceInterfaceIndexLocalOnly or indexed interface
		DNSServiceErrorType err = DNSServiceBrowse(&client, 
								flags, 
								interfaceIndex, 
								GetString(type), 
								domain?GetString(domain):NULL, 
								&callback, this);

		if(UNLIKELY(!client || err != kDNSServiceErr_NoError)) {
			post("DNSService call failed: %i",err);
			return false;
		}
		else
			return Worker::Init();
	} 
	
	const t_symbol *type,*domain;

private:
    static void DNSSD_API callback( DNSServiceRef client, 
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
		static_cast<BrowseBase *>(w->self)->OnBrowse(replyName,replyType,replyDomain,(flags & kDNSServiceFlagsAdd) != 0);
    }

};

class Browse
	: public BrowseBase
{
	FLEXT_HEADER_S(Browse,BrowseBase,Setup)
public:

	Browse(int argc,const t_atom *argv)
		: type(NULL),domain(NULL)
	{
		AddInAnything("messages");
		AddOutAnything("added/removed service");
		
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
		Update();
	}

	void ms_type(const AtomList &args)
	{
		const t_symbol *t;
		if(args.Count() == 1 && IsSymbol(args[0]))
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
		const t_symbol *d;
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

protected:
	const t_symbol *type,*domain;
	
	static const t_symbol *sym_add,*sym_remove;

	void Update()
	{
		if(type)
			Install(new BrowseWorker(this,type,domain));
		else
			Stop();
	}

    virtual void OnBrowse(const char *name,const char *type,const char *domain,bool add)
    {
/*
		std::string servname(name);
        Services::iterator it = services.find(servname);
        if(it != services.end()) return; // we already have it
        services.insert(servname);
*/
        t_atom at[3]; 
		SetString(at[0],name);
		SetString(at[1],type);
		SetString(at[2],domain);
		ToOutAnything(0,add?sym_add:sym_remove,3,at);
    }

	FLEXT_CALLVAR_V(mg_type,ms_type)
	FLEXT_CALLVAR_V(mg_domain,ms_domain)
	
	static void Setup(t_classid c)
	{
		sym_add = MakeSymbol("add");
		sym_remove = MakeSymbol("remove");
	
		FLEXT_CADDATTR_VAR(c,"type",mg_type,ms_type);
		FLEXT_CADDATTR_VAR(c,"domain",mg_domain,ms_domain);
	}
};

const t_symbol *Browse::sym_add,*Browse::sym_remove;

FLEXT_LIB_V("zconf.browse",Browse)

} //namespace

