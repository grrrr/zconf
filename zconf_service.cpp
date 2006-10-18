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
};

class ServiceWorker
	: public Worker
{
public:
	ServiceWorker(ServiceBase *s,Symbol n,Symbol t,Symbol d,int p,int i)
		: Worker(s)
		, name(n),type(t),domain(d),interf(i),port(p)
	{}
	
protected:
	typedef union { unsigned char b[2]; unsigned short NotAnInteger; } Opaque16;

	virtual bool Init()
	{
		uint16_t PortAsNumber	= port;
		Opaque16 registerPort   = { { PortAsNumber >> 8, PortAsNumber & 0xFF } };

		DNSServiceErrorType err = DNSServiceRegister(
			&client, 
			0, // flags: default renaming behaviour 
            interf < 0?kDNSServiceInterfaceIndexLocalOnly:kDNSServiceInterfaceIndexAny, 
			name?GetString(name):NULL,
			GetString(type),
			domain?GetString(domain):NULL,
			NULL, // host
			registerPort.NotAnInteger,
			0, NULL,  // txtlen,txtrecord 
			(DNSServiceRegisterReply)&callback, this
		);

		if(LIKELY(err == kDNSServiceErr_NoError)) {
			FLEXT_ASSERT(client);
			return Worker::Init();
		}
		else {
			static_cast<ServiceBase *>(self)->OnError(err);
			return false;
		}
	} 
	
	Symbol name,type,domain,text;
    int interf,port;

private:
    static void DNSSD_API callback(
        DNSServiceRef       sdRef, 
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
		
		if(LIKELY(errorCode == kDNSServiceErr_NoError))
			static_cast<ServiceBase *>(w->self)->OnRegister(name,regtype,domain);
		else
			static_cast<ServiceBase *>(w->self)->OnError(errorCode);
	}
};

class Service
	: public ServiceBase
{
	FLEXT_HEADER_S(Service,ServiceBase,Setup)
public:

	Service(int argc,const t_atom *argv)
		: name(NULL),type(NULL),domain(NULL),interf(0),port(0)
	{		
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
			if(CanbeInt(*argv)) 
				interf = GetAInt(*argv);
			else
				throw "interface must be an int";
			--argc,++argv;
		}
		Update();
	}

	void ms_name(const AtomList &args)
	{
		Symbol n;
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

	void ms_port(int p)
	{
		if(p != port) {
			port = p;
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
    /*
	void ms_text(const AtomList &args)
	{
		Symbol t;
		if(!args.Count())
			t = NULL;
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
*/

protected:

	static Symbol sym_service;

	Symbol name,type,domain;
    int interf,port;
	
	virtual void Update()
	{
		if(type)
			Install(new ServiceWorker(this,name,type,domain,port,interf));
		else
			Stop();
	}

	virtual void OnRegister(const char *name,const char *type,const char *domain)
	{
		t_atom at[3];
		SetString(at[0],name);
		SetString(at[1],type);
		SetString(at[2],domain);
		ToOutAnything(GetOutAttr(),sym_service,3,at);
	}

	FLEXT_CALLVAR_V(mg_name,ms_name)
	FLEXT_CALLVAR_V(mg_type,ms_type)
	FLEXT_CALLVAR_V(mg_domain,ms_domain)
	FLEXT_CALLSET_I(ms_port)
	FLEXT_ATTRGET_I(port)
	FLEXT_CALLSET_I(ms_interface)
	FLEXT_ATTRGET_I(interf)
//	FLEXT_CALLVAR_V(mg_text,ms_text)
	
	static void Setup(t_classid c)
	{
		sym_service = MakeSymbol("service");
	
		FLEXT_CADDATTR_VAR(c,"name",mg_name,ms_name);
		FLEXT_CADDATTR_VAR(c,"port",port,ms_port);
		FLEXT_CADDATTR_VAR(c,"type",mg_type,ms_type);
		FLEXT_CADDATTR_VAR(c,"domain",mg_domain,ms_domain);
		FLEXT_CADDATTR_VAR(c,"interface",interf,ms_interface);
//		FLEXT_CADDATTR_VAR(c,"txt",mg_text,ms_text);
	}
};

Symbol Service::sym_service;

FLEXT_LIB_V("zconf.service",Service)

} // namespace
