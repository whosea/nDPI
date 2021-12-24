#!/bin/bash
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

VER=1.0.0

function init(){

    #安装相关依赖
    yum install -y redhat-rpm-config perl kernel-devel gcc iptables-devel libpcap-devel autogen autoconf automake libtool flex bison json-c
    yum install -y json-c json-c-devel
    #rpm编译包
    yum install -y rpm-build rpmdevtools
    yum -y install zip unzip
    #初始化工作空间
    rpmdev-setuptree
#    ~/rpmbuild/SPECS	    %_specdir	Spec 文件目录	保存 RPM 包配置（.spec）文件
#    ~/rpmbuild/SOURCES	    %_sourcedir	源代码目录	保存源码包（如 .tar 包）和所有 patch 补丁
#    ~/rpmbuild/BUILD	    %_builddir	构建目录	源码包被解压至此，并在该目录的子目录完成编译
#    ~/rpmbuild/BUILDROOT	%_buildrootdir	最终安装目录	保存 %install 阶段安装的文件
#    ~/rpmbuild/RPMS	        %_rpmdir	标准 RPM 包目录	生成/保存二进制 RPM 包
#    ~/rpmbuild/SRPMS	    %_srcrpmdir	源代码 RPM 包目录	生成/保存源码 RPM 包(SRPM)

    echo "内核文件"
    ls /usr/src/kernels
    echo "内核版本"
    uname -r



    #下载源码到对应的空间
    wget -P /root https://github.com/whosea/nDPI/archive/refs/heads/flow_info-4.zip
    rm -rf /root/rpmbuild/SOURCES/flow_info-4.zip
    rm -rf /root/rpmbuild/SOURCES/nDPI-flow_info-4
    cp -f /root/flow_info-4.zip  /root/rpmbuild/SOURCES
    cd /root
    unzip /root/rpmbuild/SOURCES/flow_info-4.zip -d /root/rpmbuild/SOURCES

    echo "复制所需文件到对应rpmbuild文件夹"
    cp -rf /root/rpmbuild/SOURCES/nDPI-flow_info-4/xt-kmod/xt_ndpi-kmod.spec /root/rpmbuild/SPECS/xt_ndpi-kmod.spec
    cp -rf /root/rpmbuild/SOURCES/nDPI-flow_info-4/xt-kmod/kmodtool-xt_ndpi-el7.sh /root/rpmbuild/SOURCES/kmodtool-xt_ndpi-el7.sh
    cp -rf /root/rpmbuild/SOURCES/nDPI-flow_info-4/xt-kmod/GPL-v2.0.txt /root/rpmbuild/SOURCES/GPL-v2.0.txt

    #编译rpm包
    rpmbuild -ba /root/rpmbuild/SPECS/xt_ndpi-kmod.spec
    #编译成功后，查看输出，找到输出的rpm包
    #Wrote: /root/rpmbuild/SRPMS/xt_ndpi-kmod-2.8.2-1.el7.src.rpm
    #Wrote: /root/rpmbuild/RPMS/x86_64/kmod-xt_ndpi-2.8.2-1.el7.x86_64.rpm
    #本地安装
    yum localinstall -y /root/rpmbuild/RPMS/x86_64/kmod-xt_ndpi-2.8.2-1.el7.x86_64.rpm


    echo "模块xt_ndpi安装"
    modprobe xt_ndpi
    #验证安装成功
    cat /proc/net/xt_ndpi/proto | head -n5
    #iptables -m ndpi --help
}


usage(){
  echo "Usage: sh 执行脚本.sh [init], 必须先安装yum install dos2unix，在转dos2unix xxx.sh"
  echo "init:安装之前的环境初始化"
  exit 1
}


#yum install -y dos2unix && dos2unix ndpi-init.sh && sh ndpi-init.sh init
case "$1" in
    "init")
        init $2 $3 $4 $5
        echo 'init success'
        ;;
    *)
        usage
        ;;
esac

