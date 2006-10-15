#include "zconf.h"

#include <dns_sd.h>
#include <unistd.h>

namespace zconf {

class Browse;

class BrowserInstance
	: public flext
{
public:
	BrowserInstance(Browse *s,const t_symbol *t,const t_symbol *d)
		: self(s)
		, type(t),domain(d)
		, client(0) 
	{}
	
	~BrowserInstance()
	{
		if(client)
			DNSServiceRefDeallocate(client);
	}
	
	Browse *self;
	const t_symbol *type,*domain;
	DNSServiceRef client;
};

class Browse
	: public flext_base
{
	FLEXT_HEADER_S(Browse,flext_base,Setup)
public:

	Browse(int argc,const t_atom *argv)
		: browser(NULL)
		, type(NULL),domain(NULL)
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

	virtual ~Browse()
	{
		Stop();
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
//	typedef std::set<std::string> Services;
//    Services services;
	
	BrowserInstance *browser;
	const t_symbol *type,*domain;
	
	static const t_symbol *sym_add,*sym_remove;

	void Stop()
	{
		if(browser) {
			browser->self = NULL;
			browser = NULL;
		}
	}

	void Update()
	{
		Stop();
		if(type) {
			browser = new BrowserInstance(this,type,domain);
			t_int data = (t_int)browser;
			sys_callback(IdleFunction,&data,1);
//			services.clear();
		}
		else
			browser = NULL;
	}

	static t_int IdleFunction(t_int *data)
	{
		BrowserInstance *inst = (BrowserInstance *)data[0];
		Browse *self = inst->self;
		if(!self) {
			delete inst;
			return 0; // stopped - don't run again
		}
		
		DNSServiceErrorType err;
        
		if(UNLIKELY(!inst->client)) {
			DNSServiceFlags flags	= 0;		// default renaming behaviour 
			uint32_t interfaceIndex = kDNSServiceInterfaceIndexAny;		// all interfaces 
			err = DNSServiceBrowse(&inst->client, 
									flags, 
									interfaceIndex, 
									GetString(inst->type), 
									inst->domain?GetString(inst->domain):NULL, 
									(DNSServiceBrowseReply)&browse_reply, 
									inst);

			if(UNLIKELY(!inst->client || err != kDNSServiceErr_NoError)) {
				post("DNSService call failed: %i",err);
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

    static void DNSSD_API browse_reply( DNSServiceRef client, 
                                        const DNSServiceFlags flags,
                                        uint32_t ifIndex, 
                                        DNSServiceErrorType errorCode,
                                        const char *replyName, 
                                        const char *replyType, 
                                        const char *replyDomain,                             
                                        void *context)
    {
        BrowserInstance *inst = (BrowserInstance *)context;
		if(inst->self)
			inst->self->OnDiscover(replyName,replyType,replyDomain,(flags & kDNSServiceFlagsAdd) != 0);
    }

    void OnDiscover(const char *name,const char *type,const char *domain,bool add)
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

