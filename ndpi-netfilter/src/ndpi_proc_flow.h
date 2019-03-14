
void nflow_proc_read_start(struct ndpi_net *n);

int nflow_proc_open(struct inode *inode, struct file *file); 

int nflow_proc_close(struct inode *inode, struct file *file);

ssize_t ndpi_dump_acct_info(struct ndpi_net *n,char *buf, size_t buflen,struct nf_ct_ext_ndpi *ct);

ssize_t nflow_proc_read(struct file *file, char __user *buf, size_t count, loff_t *ppos);
ssize_t nflow_proc_write(struct file *file, const char __user *buffer, size_t length, loff_t *loff);

loff_t nflow_proc_llseek(struct file *file, loff_t offset, int whence);
