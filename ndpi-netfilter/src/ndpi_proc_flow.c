#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/atomic.h>
#include <linux/init.h>
#include <linux/proc_fs.h>

#include <linux/ip.h>
#include <linux/ipv6.h>

#include "ndpi_config.h"
#undef HAVE_HYPERSCAN
#include "ndpi_main.h"

#include "ndpi_main_common.h"
#include "ndpi_strcol.h"
#include "ndpi_main_netfilter.h"
#include "ndpi_proc_flow.h"
#include "ndpi_proc_generic.h"

void nflow_proc_read_start(struct ndpi_net *n) {
	struct timespec tm;

	getnstimeofday(&tm);
	n->acc_end  = 0;
	n->acc_open_time = tm.tv_sec;
	n->flow_l   = NULL;
	n->cnt_view = 0;
	n->cnt_del  = 0;
	n->cnt_out  = 0;
}


static ssize_t acct_info_len = 256;
ssize_t ndpi_dump_acct_info(struct ndpi_net *n,char *buf, size_t buflen,
		struct nf_ct_ext_ndpi *ct) {
	const char *t_proto;
	ssize_t l = 0;
	*buf = 0;

	buflen -= 2; // space for \n \0
	l = snprintf(buf,buflen,"%u %u %c %d ",
		ct->flinfo.time_start,ct->flinfo.time_end,
		ct->ipv6 ? '6':'4', ct->l4_proto);
	if(ct->ipv6) {
	    l += snprintf(&buf[l],buflen-l,"%pI6c %d %pI6c %d %llu %llu %u %u ",
		&ct->flinfo.ip_s, htons(ct->flinfo.sport),
		&ct->flinfo.ip_d, htons(ct->flinfo.dport),
		ct->flinfo.b[0]-ct->flinfo.b[2],
		ct->flinfo.b[1]-ct->flinfo.b[3],
		ct->flinfo.p[0]-ct->flinfo.p[2],
		ct->flinfo.p[1]-ct->flinfo.p[3]);
	} else {
	    l += snprintf(&buf[l],buflen-l,"%pI4n %d %pI4n %d %llu %llu %u %u",
		&ct->flinfo.ip_s, htons(ct->flinfo.sport),
		&ct->flinfo.ip_d, htons(ct->flinfo.dport),
		ct->flinfo.b[0]-ct->flinfo.b[2],
		ct->flinfo.b[1]-ct->flinfo.b[3],
		ct->flinfo.p[0]-ct->flinfo.p[2],
		ct->flinfo.p[1]-ct->flinfo.p[3]);
	}

	l += snprintf(&buf[l],buflen-l," I=%d,%d",ct->flinfo.ifidx,ct->flinfo.ofidx);
#if defined(CONFIG_NF_CONNTRACK_MARK)
	if(ct->connmark)
	    l += snprintf(&buf[l],buflen-l," CM=%x",ct->connmark);
#endif
	if(!ct->ipv6) {
	    if(ct->snat) {
		l += snprintf(&buf[l],buflen-l," SN=%pI4n:%d",
				&ct->flinfo.ip_snat,htons(ct->flinfo.sport_nat));
	    }
	    if(ct->dnat) {
		l += snprintf(&buf[l],buflen-l," DN=%pI4n:%d",
				&ct->flinfo.ip_dnat,htons(ct->flinfo.dport_nat));
	    }
#ifdef USE_HACK_USERID
	    if(ct->userid) {
		l += snprintf(&buf[l],buflen-l," UI=%pI4n:%d",
				&ct->flinfo.ip_snat,htons(ct->flinfo.sport_nat));
	    }
#endif
	}
	t_proto = ndpi_get_proto_by_id(n->ndpi_struct,ct->proto.app_protocol);
	l += snprintf(&buf[l],buflen-l," P=%s",t_proto);
	if(ct->proto.master_protocol != NDPI_PROTOCOL_UNKNOWN) {
	    t_proto = ndpi_get_proto_by_id(n->ndpi_struct,ct->proto.master_protocol);
	    l += snprintf(&buf[l],buflen-l,".%s",t_proto);
	}
	if(ct->ssl)
	    l += snprintf(&buf[l],buflen-l," C=%s",ct->ssl);
	if(ct->host)
	    l += snprintf(&buf[l],buflen-l," H=%s",ct->host);

	buf[l] = 0;
	if(l > acct_info_len ) {
		printk("%s: max len %d\n'%s'\n",__func__,(int)l, buf);
		acct_info_len = l;
	}
	buf[l++] = '\n';
	buf[l] = 0;
	return l;
}


ssize_t nflow_proc_read(struct file *file, char __user *buf,
                              size_t count, loff_t *ppos)
{
        struct ndpi_net *n = PDE_DATA(file_inode(file));
	return nflow_read(n, buf, count, ppos);
}

static int parse_ndpi_flow(struct ndpi_net *n,char *buf)
{
	int idx;

	if(!ndpi_enable_flow) return -EINVAL;

        if(!buf[0]) return 0;

	if(sscanf(buf,"timeout=%d",&idx) == 1) {
		if(idx < 1 || idx > 600) return -EINVAL;
		n->acc_wait = idx;
		printk("%s: set timeout=%d\n",__func__,n->acc_wait);
	} else if(sscanf(buf,"limit=%d",&idx) == 1) {
		if(idx < atomic_read(&n->acc_work) || idx > ndpi_flow_limit)
			return -EINVAL;
		n->acc_limit = idx;
		printk("%s: set limit=%d\n",__func__,n->acc_limit);
	} else if(!strcmp(buf,"read_closed")) {
		if(n->acc_end || !n->flow_l) {
			n->acc_read_mode = 1;
		} else return -EINVAL;
		printk("%s: set read_mode=%d\n",__func__,n->acc_read_mode);
	} else if(!strcmp(buf,"read_flows")) {
		if(n->acc_end || !n->flow_l) {
			n->acc_read_mode = 2;
		} else return -EINVAL;
		printk("%s: set read_mode=%d\n",__func__,n->acc_read_mode);
	} else if(!strcmp(buf,"read_all")) {
		if(n->acc_end || !n->flow_l) {
			n->acc_read_mode = 0;
		} else return -EINVAL;
		printk("%s: set read_mode=%d\n",__func__,n->acc_read_mode);
	} else
		return -EINVAL;
	return 0;
}

int nflow_proc_open(struct inode *inode, struct file *file) {
        struct ndpi_net *n = PDE_DATA(file_inode(file));

	if(!ndpi_enable_flow) return -EINVAL;

	if(atomic_xchg(&n->acc_open,1)) {
		return -EBUSY;
	}
	n->acc_read_mode = 0;
	if(!n->acc_wait) n->acc_wait = 60;
	nflow_proc_read_start(n);
	return 0;
}

int nflow_proc_close(struct inode *inode, struct file *file)
{
        struct ndpi_net *n = PDE_DATA(file_inode(file));
	if(!ndpi_enable_flow) return -EINVAL;
	generic_proc_close(n,parse_ndpi_flow,W_BUF_FLOW);
	if(flow_read_debug)
		printk("%s: view %ld dumped %ld deleted %ld\n",
			__func__,n->cnt_view,n->cnt_out,n->cnt_del);
	n->acc_gc = jiffies + n->acc_wait*HZ;
	atomic_set(&n->acc_open,0);
        return 0;
}

ssize_t
nflow_proc_write(struct file *file, const char __user *buffer,
		                     size_t length, loff_t *loff)
{
	if(!ndpi_enable_flow) return -EINVAL;
	return generic_proc_write(PDE_DATA(file_inode(file)), buffer, length, loff,
				  parse_ndpi_flow, 4060 , W_BUF_FLOW);
}

loff_t nflow_proc_llseek(struct file *file, loff_t offset, int whence) {
	if(whence == SEEK_SET) {
		struct ndpi_net *n = PDE_DATA(file_inode(file));
		if(offset == 0) {
			nflow_proc_read_start(n);
			return vfs_setpos(file,offset,OFFSET_MAX);
		}
		if(offset >= atomic_read(&n->acc_work)) {
			n->acc_end = 1;
			n->flow_l = NULL;
			return vfs_setpos(file,atomic_read(&n->acc_work),OFFSET_MAX);
		}
	}
	if(whence == SEEK_CUR && offset == 0) {
		return noop_llseek(file,offset,whence);
	}
	return -EINVAL;
}

