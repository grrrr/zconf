#include "zconf.h"

#include <dns_sd.h>

namespace zconf {

class Resolve;

class ResolverInstance
	: public flext
{
public:
	ResolverInstance(Resolve *s,const t_symbol *n,const t_symbol *t,const t_symbol *d)
		: self(s)
		, name(n),type(t),domain(d)
		, client(0) 
	{}
	
	~ResolverInstance()
	{
        if(client) 
			DNSServiceRefDeallocate(client);
	}
	
	Resolve *self;
	const t_symbol *name,*type,*domain;
	DNSServiceRef client;
};

class Resolve
	: public flext_base
{
	FLEXT_HEADER_S(Resolve,flext_base,Setup)
public:

	Resolve()
	{
		AddInAnything("messages");
		AddOutAnything("resolved host and port for service name");
	}

	~Resolve()
	{
		if(resolve) 
			resolve->self = NULL;
	}

	void m_resolve(int argc,const t_atom *argv)
	{
		if(argc < 2 || !IsSymbol(argv[0]) || !IsSymbol(argv[1]))
			throw "name and type must be given as symbols";		
		const t_symbol *name = GetSymbol(argv[0]);
		const t_symbol *type = GetSymbol(argv[1]);
		
		const t_symbol *domain;
		if(argc == 2)
			domain = NULL;
		else if(argc == 3 && IsSymbol(argv[2]))
			domain = GetSymbol(argv[2]);
		else
			throw "domain must be given as a symbol (or omitted)";

		resolve = new ResolverInstance(this,name,type,domain);
		t_int data = (t_int)resolve;
		sys_callback(IdleFunction,&data,1);
	}

protected:

    ResolverInstance *resolve;

	void Stop()
	{
		if(resolve) {
			resolve->self = NULL;
			resolve = NULL;
		}
	}

	static t_int IdleFunction(t_int *data)
	{
		ResolverInstance *inst = (ResolverInstance *)data[0];
		Resolve *self = inst->self;
		if(!self) {
			delete inst;
			return 0; // stopped - don't run again
		}
		
        
		FLEXT_ASSERT(!inst->client);

		DNSServiceFlags flags	= 0;		// default renaming behaviour 
		uint32_t interfaceIndex = kDNSServiceInterfaceIndexAny;		// all interfaces 
		DNSServiceErrorType err;
		err = DNSServiceResolve(&inst->client,
								flags,
								interfaceIndex,
								GetString(inst->name),
								GetString(inst->type),
								inst->domain?GetString(inst->domain):NULL,
								(DNSServiceResolveReply)&resolve_reply,
								inst);

		if(UNLIKELY(!inst->client || err != kDNSServiceErr_NoError))
			post("DNSService call failed: %i",err);

		return 0;
	}

    static void DNSSD_API resolve_reply(DNSServiceRef client, 
                                        const DNSServiceFlags flags, 
                                        uint32_t ifIndex, 
                                        DNSServiceErrorType errorCode,
	                                    const char *fullname, 
                                        const char *hosttarget, 
                                        uint16_t opaqueport, 
                                        uint16_t txtLen, 
                                        const char *txtRecord, 
                                        void *context)
	{
        ResolverInstance *inst = (ResolverInstance *)context;

    	union { uint16_t s; unsigned char b[2]; } port = { opaqueport };
	    uint16_t PortAsNumber = ((uint16_t)port.b[0]) << 8 | port.b[1];

		if(inst->self) {
			inst->self->OnResolve(fullname,hosttarget,PortAsNumber,txtRecord);
			inst->self->Stop();
		}

        // Note: When the desired results have been returned, 
        // the client MUST terminate the resolve by calling DNSServiceRefDeallocate().
		delete inst;
    }

    void OnResolve(const char *fullName,const char *hostTarget,int port,const char *txtRecord)
    {
		t_atom at[3];
		SetString(at[0],fullName);
		SetString(at[1],hostTarget);
		SetInt(at[2],port);
		ToOutList(0,3,at);
    }

	FLEXT_CALLBACK_V(m_resolve)

	static void Setup(t_classid c)
	{
		FLEXT_CADDMETHOD(c,0,m_resolve);
	}
};

FLEXT_LIB("zconf.resolve",Resolve)

} // namespace
