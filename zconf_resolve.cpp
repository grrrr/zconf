#include "zconf.h"

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

	virtual ~Resolve()
	{
		Stop();
	}

	void m_resolve(int argc,const t_atom *argv)
	{
		if(argc < 1 || !IsSymbol(argv[0])) {
			post("%s - %s: type (like _ssh._tcp or _osc._udp) must be given at least",thisName(),GetString(thisTag()));
			return;
		}
		
		const t_symbol *type = GetSymbol(argv[0]);
		const t_symbol *name = argc >= 2?GetASymbol(argv[1]):NULL;
		const t_symbol *domain = argc >= 3?GetASymbol(argv[2]):NULL;

		Stop();
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
		
		if(!inst->client) {
			DNSServiceFlags flags	= 0;		// default renaming behaviour 
			uint32_t interfaceIndex = kDNSServiceInterfaceIndexAny;		// all interfaces 
			DNSServiceErrorType err;
			err = DNSServiceResolve(&inst->client,
									flags,
									interfaceIndex,
									inst->name?GetString(inst->name):NULL,
									GetString(inst->type),
									inst->domain?GetString(inst->domain):NULL,
									(DNSServiceResolveReply)&resolve_reply,
									inst);

			if(UNLIKELY(!inst->client || err != kDNSServiceErr_NoError))
				post("DNSService call failed: %i",err);
				
			return 1; // call it again as soon as possible
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
				DNSServiceErrorType err = DNSServiceProcessResult(inst->client);
				if(UNLIKELY(err))
					post("DNSServiceProcessResult call failed: %i",err);
			}
			
			return 1; // call again to free the resources
		}
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
//		delete inst;
    }

    void OnResolve(const char *fullName,const char *hostTarget,int port,const char *txtRecord)
    {
		t_atom at[4];
		SetString(at[0],fullName);
		SetString(at[1],hostTarget);
		SetInt(at[2],port);
		bool txt = txtRecord && *txtRecord;
		if(txt) SetString(at[3],txtRecord);
		ToOutList(0,txt?4:3,at);
    }

	FLEXT_CALLBACK_V(m_resolve)

	static void Setup(t_classid c)
	{
		FLEXT_CADDMETHOD(c,0,m_resolve);
	}
};

FLEXT_LIB("zconf.resolve",Resolve)

} // namespace
