/* 
zconf - zeroconf networking objects

Copyright (c)2006 Thomas Grill (gr@grrrr.org)
For information on usage and redistribution, and for a DISCLAIMER OF ALL
WARRANTIES, see the file, "license.txt," in this distribution.  
*/

#include "zconf.h"

namespace zconf {

class ServiceBase
	: public Base
{
public:
	virtual void OnRegister(const char *name,const char *type,const char *domain) = 0;
	virtual void OnError(const char *why) = 0;
};

class ServiceWorker
	: public Worker
{
public:
	ServiceWorker(ServiceBase *s,const t_symbol *n,const t_symbol *t,const t_symbol *d,int p,const t_symbol *tx)
		: Worker(s)
		, name(n),type(t),domain(d),text(tx),port(p)
	{}
	
protected:
//	typedef union { unsigned char b[2]; unsigned short NotAnInteger; } Opaque16;

	virtual bool Init()
	{
		DNSServiceFlags flags	= 0;		                        // default renaming behaviour 
		uint32_t interfaceIndex = kDNSServiceInterfaceIndexAny;		// all interfaces 
//			uint16_t PortAsNumber	= inst->port;
//			Opaque16 registerPort   = { { PortAsNumber >> 8, PortAsNumber & 0xFF } };
		const char *txtrec = text?GetString(text):NULL;

		DNSServiceErrorType err = DNSServiceRegister(
			&client, 
			flags, 
			interfaceIndex, 
			name?GetString(name):NULL,
			GetString(type),
			domain?GetString(domain):NULL,
			NULL, // host
			port, // registerPort.NotAnInteger,
			txtrec?strlen(txtrec)+1:0, txtrec,  // txtlen,txtrecord 
			(DNSServiceRegisterReply)&callback, this
		);

		if(UNLIKELY(!client || err != kDNSServiceErr_NoError)) {
			post("DNSService call failed: %i",err);
			return false;
		}
		else
			return Worker::Init();
	} 
	
	const t_symbol *name,*type,*domain,*text;
	int port;

private:
    static void DNSSD_API callback(   DNSServiceRef       sdRef, 
                                            DNSServiceFlags     flags, 
                                            DNSServiceErrorType errorCode, 
                                            const char          *name, 
                                            const char          *regtype, 
                                            const char          *domain, 
                                            void                *context ) 
	{
        // do something with the values that have been registered
        ServiceWorker *w = (ServiceWorker *)context;
		FLEXT_ASSERT(w->self);
		switch(errorCode) {
			case kDNSServiceErr_NoError:      
				static_cast<ServiceBase *>(w->self)->OnRegister(name,regtype,domain);
				break;
			case kDNSServiceErr_NameConflict: 
				static_cast<ServiceBase *>(w->self)->OnError("name_in_use");
				break;
			default:
				static_cast<ServiceBase *>(w->self)->OnError("unknown");
		}
	}
};

class Service
	: public ServiceBase
{
	FLEXT_HEADER_S(Service,ServiceBase,Setup)
public:

	Service(int argc,const t_atom *argv)
		: name(NULL),type(NULL),domain(NULL),text(NULL),port(0)
	{
		AddInAnything("messages");
		AddOutAnything("real registered service name");
		
		if(argc >= 1) {
			if(IsSymbol(*argv)) 
				type = GetSymbol(*argv);
			else
				throw "type must be a symbol";
			--argc,++argv;
		}
		if(argc >= 1) {
			if(CanbeInt(*argv)) 
				port = GetAInt(*argv);
			else
				throw "port must be a int";
			--argc,++argv;
		}
		if(argc >= 1) {
			if(IsSymbol(*argv)) 
				name = GetSymbol(*argv);
			else
				throw "name must be a symbol";
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
			if(IsSymbol(*argv)) 
				text = GetSymbol(*argv);
			else
				throw "domain must be a symbol";
			--argc,++argv;
		}
		Update();
	}

	void ms_name(const AtomList &args)
	{
		const t_symbol *n;
		if(!args.Count())
			n = NULL;
		else if(args.Count() == 1 && IsSymbol(args[0]))
			n = GetSymbol(args[0]);
		else {
			post("%s - name [symbol]",thisName());
			return;
		}

		if(n != name) {
			name = n;
			Update();
		}
	}

	void mg_name(AtomList &args) const { if(name) { args(1); SetSymbol(args[0],name); } }

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

	void ms_port(int p)
	{
		if(p != port) {
			port = p;
			Update();
		}
	}

	void ms_text(const AtomList &args)
	{
		const t_symbol *t;
		if(args.Count() == 1 && IsSymbol(args[0]))
			t = GetSymbol(args[0]);
		else {
			post("%s - text [symbol]",thisName());
			return;
		}

		if(t != text) {
			text = t;
			Update();
		}
	}

	void mg_text(AtomList &args) const { if(text) { args(1); SetSymbol(args[0],text); } }


protected:

	const t_symbol *name,*type,*domain,*text;
	int port;
	
	static const t_symbol *sym_error;

	void Update()
	{
		if(type && port)
			Install(new ServiceWorker(this,name,type,domain,port,text));
		else
			Stop();
	}

	virtual void OnRegister(const char *name,const char *type,const char *domain)
	{
		t_atom at[3];
		SetString(at[0],name);
		SetString(at[1],type);
		SetString(at[2],domain);
		ToOutList(0,3,at);
	}

	virtual void OnError(const char *why)
	{
		t_atom at;
		SetString(at,why);
		ToOutAnything(0,sym_error,1,&at);
	}

	FLEXT_CALLVAR_V(mg_name,ms_name)
	FLEXT_CALLVAR_V(mg_type,ms_type)
	FLEXT_CALLVAR_V(mg_domain,ms_domain)
	FLEXT_CALLSET_I(ms_port)
	FLEXT_ATTRGET_I(port)
	FLEXT_CALLVAR_V(mg_text,ms_text)
	
	static void Setup(t_classid c)
	{
		sym_error = MakeSymbol("error");
	
		FLEXT_CADDATTR_VAR(c,"name",mg_name,ms_name);
		FLEXT_CADDATTR_VAR(c,"port",port,ms_port);
		FLEXT_CADDATTR_VAR(c,"type",mg_type,ms_type);
		FLEXT_CADDATTR_VAR(c,"domain",mg_domain,ms_domain);
		FLEXT_CADDATTR_VAR(c,"text",mg_text,ms_text);
	}
};

const t_symbol *Service::sym_error;

FLEXT_LIB_V("zconf.service",Service)

} // namespace
