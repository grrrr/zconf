#include "zconf.h"

#include <dns_sd.h>
#include <unistd.h>

namespace zconf {

class Service;

class ServiceInstance
	: public flext
{
public:
	ServiceInstance(Service *s,const t_symbol *n,const t_symbol *t,const t_symbol *d,int p)
		: self(s)
		, name(n),type(t),domain(d),port(p)
		, client(0) 
	{}
	
	~ServiceInstance()
	{
        if(client) 
			DNSServiceRefDeallocate(client);
	}
	
	Service *self;
	const t_symbol *name,*type,*domain;
	int port;
	DNSServiceRef client;
};

class Service
	: public flext_base
{
	FLEXT_HEADER_S(Service,flext_base,Setup)
public:

	Service(int argc,const t_atom *argv)
		: service(NULL)
		, name(NULL),type(NULL),domain(NULL),port(0)
	{
		AddInAnything("messages");
		AddOutAnything("real registered service name");
		
		if(argc >= 1) {
			if(IsSymbol(*argv)) 
				name = GetSymbol(*argv);
			else
				throw "name must be a symbol";
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

	virtual ~Service()
	{
        Stop();
	}

	void ms_name(const AtomList &args)
	{
		const t_symbol *n;
		if(args.Count() == 1 && IsSymbol(args[0]))
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

protected:

    ServiceInstance *service;
	const t_symbol *name,*type,*domain;
	int port;
	
	static const t_symbol *sym_error;

	void Stop()
	{
		if(service) {
			service->self = NULL;
			service = NULL;
		}
	}

	void Update()
	{
		Stop();
		if(name && type && port) {
			service = new ServiceInstance(this,name,type,domain,port);
			t_int data = (t_int)service;
			sys_callback(IdleFunction,&data,1);
		}	
		else
			service = NULL;
	}

	typedef union { unsigned char b[2]; unsigned short NotAnInteger; } Opaque16;

	static t_int IdleFunction(t_int *data)
	{
		ServiceInstance *inst = (ServiceInstance *)data[0];
		Service *self = inst->self;
		if(!self) {
			delete inst;
			return 0; // stopped - don't run again
		}
		
		DNSServiceErrorType err;
			
		if(UNLIKELY(!inst->client)) {

			DNSServiceFlags flags	= 0;		                        // default renaming behaviour 
			uint32_t interfaceIndex = kDNSServiceInterfaceIndexAny;		// all interfaces 
			uint16_t PortAsNumber	= inst->port;
			Opaque16 registerPort   = { { PortAsNumber >> 8, PortAsNumber & 0xFF } };

			DNSServiceErrorType result = DNSServiceRegister(
				&inst->client, 
				flags, 
				interfaceIndex, 
				GetString(inst->name),
				GetString(inst->type),
				inst->domain?GetString(inst->domain):NULL,
				"", // host
				registerPort.NotAnInteger,
				0, "",  // txtlen,txtrecord 
				(DNSServiceRegisterReply)&register_reply, inst
			);

			if(UNLIKELY(!inst->client || err != kDNSServiceErr_NoError)) {
				post("DNSServiceRegister call failed: %i",err);
				return 2;
			}
			else
				return 1; // call again as soon as possible			
		}
		else {
			int dns_sd_fd = DNSServiceRefSockFD(inst->client);
			int nfds = dns_sd_fd+1;
			fd_set readfds;
			
			FD_ZERO(&readfds);
			FD_SET(dns_sd_fd,&readfds);
			timeval tv; tv.tv_sec = tv.tv_usec = 0; // don't block
			int result = select(nfds,&readfds,NULL,NULL,&tv);
			if(UNLIKELY(result > 0)) {
				FLEXT_ASSERT(FD_ISSET(dns_sd_fd,&readfds));
				err = DNSServiceProcessResult(inst->client);
				if(UNLIKELY(err))
					post("DNSServiceProcessResult call failed: %i",err);
			}
			
			return 2; // call again on next cycle
		}
	}

    static void DNSSD_API register_reply(   DNSServiceRef       sdRef, 
                                            DNSServiceFlags     flags, 
                                            DNSServiceErrorType errorCode, 
                                            const char          *name, 
                                            const char          *regtype, 
                                            const char          *domain, 
                                            void                *context ) {
        // do something with the values that have been registered
        ServiceInstance *inst = (ServiceInstance *)context;
		if(inst->self) {
			switch (errorCode)
			{
				case kDNSServiceErr_NoError:      
					inst->self->OnRegister(name,regtype,domain);
					break;
				case kDNSServiceErr_NameConflict: 
					inst->self->OnError("name_in_use");
					break;
				default:
					inst->self->OnError("unknown");
			}
		}
	}

	void OnRegister(const char *name,const char *type,const char *domain)
	{
		t_atom at[3];
		SetString(at[0],name);
		SetString(at[1],type);
		SetString(at[2],domain);
		ToOutList(0,3,at);
	}

	void OnError(const char *why)
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
	
	static void Setup(t_classid c)
	{
		sym_error = MakeSymbol("error");
	
		FLEXT_CADDATTR_VAR(c,"name",mg_name,ms_name);
		FLEXT_CADDATTR_VAR(c,"port",port,ms_port);
		FLEXT_CADDATTR_VAR(c,"type",mg_type,ms_type);
		FLEXT_CADDATTR_VAR(c,"domain",mg_domain,ms_domain);
	}
};

const t_symbol *Service::sym_error;

FLEXT_LIB_V("zconf.service",Service)

} // namespace
