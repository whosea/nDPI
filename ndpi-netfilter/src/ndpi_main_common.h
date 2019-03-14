
struct ndpi_net;

int inet_ntop_port(int family,void *ip, u_int16_t port, char *lbuf, size_t bufsize);
int ndpi_delete_acct(struct ndpi_net *n,int all,int start);
ssize_t nflow_read(struct ndpi_net *n, char __user *buf,
	            size_t count, loff_t *ppos);

extern unsigned long  ndpi_acc_limit;
extern unsigned long  bt_hash_size;
extern unsigned long  bt6_hash_size;
extern unsigned long  bt_hash_tmo;
extern unsigned long  ndpi_enable_flow;
extern struct kmem_cache *ct_info_cache;

#define XCHGP(a,b) { void *__c = a; a = b; b = __c; }

