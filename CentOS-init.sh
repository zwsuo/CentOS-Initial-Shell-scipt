#!/bin/bash
# des: system_init_shell
shopt -s extglob
 
if [[ "$(whoami)" != "root" ]]; then
    echo "请在root环境下运行此脚本 ." >&2
    exit 1
fi
  
echo -e "\033[33m 这个是centos系统初始化脚本，请慎重运行！ press ctrl+C 取消 \033[0m"

#####公共变量start####
###线上IP###
aliShaOnline='@(192.168.1|192.168.2)'
aliHuaBei2cOnline='@(192.168.3|192.168.4|)'
aliHuaBei2eOnline='@(192.168.5|192.168.6|)'
azure='@(192.168.7)'
###线上IP###
###测试IP###
aliHuaBei2eTest='@(10.10.1|10.10.2|10.10.3)'
###测试IP###
#####公共变量end####
####公共函数start###
#### 判断命令行的参数个数
function usage(){
	if [ $# -gt 1 ] ; then
       	 echo "USAGE: $0 NUM"
       	 exit 1;
	fi 
}
##判断系统version
os_version(){
    #version=`cat /etc/*release|grep -i VERSION_ID|awk -F '"' '{print $2}'`
    subVersion=`cat /etc/redhat-release|grep -Po '\d.(\d.)?(\d)+'`
       version=${subVersion%%.*}
	if   [[ $version -eq 7 ]];then
		echo 7
        elif [[ $version -eq 6 ]];then
                echo 6
        else
		echo 'unknown' 
        fi
}
##打印结果
printResultOk ()
{
        echo -e "\033[32m [完毕] \033[0m"
}
printResultIgnore ()
{
        echo -e "\033[32m [忽略] \033[0m"
}
printResultErr ()
{
        echo -e "\033[31m [错误] \033[0m"
}
##sleep
sleepProcess ()
{
        sleep 1;
}
##redirect /dev/null
devNull ()
{
	echo '>/dev/null 2>71'
}
###提示
hint ()
{
       echo -e "\033[01m提示:【初始化配置完毕，请根据需要手动重启机器】\033[0m"
}
###获取本机IP
getIp ()
{
	ip=`/sbin/ifconfig -a|grep -i ^$1 -A 7|grep inet|grep -v 127.0.0.1|grep -v inet6|awk '{print $2}'|tr -d "addr:"`
	echo $ip
}
###删除和添加i选项
delChattrFlag()
{
        if [ ! -w /etc/resolv.conf ];then
                chattr -i /etc/resolv.conf
        fi
}

addChattrFlag()
{
        if [ -w /etc/resolv.conf ];then
                chattr +i /etc/resolv.conf
        fi
}
###
cmdbClientDownload()
{
        wget -q -O /etc/cron.d/cmdb.cron http://my.inner.domain/xxxx/xxxx/cmdb.cron  >/dev/null 2>&1
        wget -q -O /usr/local/sbin/cmdb.py http://my.inner.domain/xxxx/xxxx/cmdb.py  >/dev/null 2>&1 
}
###检测到yum源私有库的网络连通性###
function networkCheck()    
{     
    timeout=10       
    target=my.inner.domain       
    retCode=`curl -I -s -o /dev/null --connect-timeout $timeout $target -w %{http_code}`    
    
    if [[ "x$retCode" != "x200" ]]; then
        echo -n [本机到yum源-http://my.inner.domain 不通，请检查] && printResultErr && exit 1
    fi    
}  
motdCaseRegion()
{
	ipAddr=`getIp eth0`
	ipFilter=${ipAddr%.*}

	case $ipFilter in
	        $aliShaOnline)
			sed -i 's/生产系统/阿里云-上海A区【线上】生产/g' /usr/local/bin/dynmodtd >/dev/null 2>&1
	                res=0
	                ;;
	        $aliHuaBei2cOnline)
			sed -i 's/生产系统/阿里云-华北C区【线上】生产/g' /usr/local/bin/dynmodtd  >/dev/null 2>&1
	                res=0
	                ;;
	        $aliHuaBei2eOnline)
			sed -i 's/生产系统/阿里云-华北E区【线上】生产/g' /usr/local/bin/dynmodtd  >/dev/null 2>&1
	                res=0
	                ;;
	        $aliHuaBei2eTest)
			sed -i 's/生产系统/阿里云-华北E区【测试】/g' /usr/local/bin/dynmodtd  >/dev/null 2>&1
	                res=0
	                ;;
	        $azure)
			sed -i 's/生产系统/微软云/g' /usr/local/bin/dynmodtd  >/dev/null 2>&1
	                res=0
	                ;;
	        *)
			sed -i 's/生产系统/亚马逊云/g' /usr/local/bin/dynmodtd  >/dev/null 2>&1
	                res=0
			;;
	esac
}
###判断yum是否成功安装了包###
function isInstalled {
  if rpm -q  "$@" >/dev/null 2>&1; then
    true
  else
    false
  fi
}

####公共函数end###
  
###set hostname #####
hostNameSet()
{
hostName=`hostname`
dashNumbers=`echo $hostName|grep -o '-'|wc -l`
if [[ $dashNumbers != 4 ]];then
    echo -n "请填写主机名【必须首先设置】:"
    while read hostName
    do
        dashNumbers=`echo $hostName|grep -o '-'|wc -l`
        if [[ $dashNumbers != 4 ]];then
            echo -n "请填写主机名【必须首先设置】:"
            continue
        else
            break
        fi
    done

ver=`os_version`
    if [[ $ver -eq 7 ]];then
        hostnamectl set-hostname $hostName
    elif [[ $ver -eq 6 ]];then
	cat <<- EOF > /etc/sysconfig/network
	NETWORKING=yes
	NETWORKING_IPV6=no
	PEERNTP=no
	HOSTNAME=$hostName
	EOF
    fi
fi
}
####set motd### 
motdSet()
{
	[ -x "/etc/rc.d/rc.local" ] || chmod +x /etc/rc.d/rc.local
	wget -O /usr/local/bin/dynmodtd http://my.inner.domain/xxx/motd/dynmodtd  >/dev/null 2>&1
	chmod +x /usr/local/bin/dynmodtd
	grep 'motd begin' /etc/profile 2>&1 >/dev/null
        [[ $? == 0 ]] && (echo -n motd && printResultIgnore) && return
	ver=`os_version`
	if [[ $ver -eq 7 ]];then
		cat <<- EOF >>/etc/profile
			####motd begin####
			/usr/local/bin/dynmodtd	
			PS1="\[\e[0m\][\u@\[\e[32;1m\]`/sbin/ifconfig eth0 | grep "inet " | awk '{print $2}'`\[\e[0m\] \W]# "
			export PS1
			####motd end####
		EOF
		motdCaseRegion
	fi
	if [[ $ver -eq 6 ]];then
		cat <<- EOF >>/etc/profile
			####motd begin####
			/usr/local/bin/dynmodtd	
			PS1="\[\e[0m\][\u@\[\e[32;1m\]`/sbin/ifconfig eth0 | grep "inet addr" | sed -e "s/^.*inet addr:\(.*\) Bcast.*$/\1/"`\[\e[0m\] \W]# "
			export PS1
			####motd end####
		EOF
		motdCaseRegion
	fi
    	[[ $? == 0 ]] && (echo -n motd配置 && printResultOk) || (echo -n motd配置 && printResultErr)
}
  
#update system pack
yum_update(){
    yum -y install wget >/dev/null 2>&1
    cd /etc/yum.repos.d/
    [ ! -d bak ] && mkdir bak
    mv ./*.repo bak
     ver=`os_version`
     if [[ $ver -eq 7 ]];then
    	wget -q -O /etc/yum.repos.d/CentOS-Base.repo http://my.inner.domain/xxx/repo/vhall/Centos-7.repo >/dev/null 2>&1
    	wget -q -O /etc/yum.repos.d/epel.repo http://my.inner.domain/xxx/repo/vhall/epel-7.repo >/dev/null 2>&1
     else
    	wget -q -O /etc/yum.repos.d/CentOS-Base.repo http://my.inner.domain/xxx/repo/vhall/Centos-6.repo >/dev/null 2>&1
    	wget -q -O /etc/yum.repos.d/epel.repo http://my.inner.domain/xxx/xxx/vhall/epel-6.repo >/dev/null 2>&1
     fi
    wget -q http://my.inner.domain/xxx/repo/vhall/my.repo
	sed -i 's/baseurl=/#baseurl=/;s/#mirrorlist=/mirrorlist=/'  CentOS-Base.repo
	sed -i 's/baseurl=/#baseurl=/;s/#mirrorlist=/mirrorlist=/'  epel.repo
    #yum clean all && yum makecache
    [[ $? == 0 ]] && (echo -n yum源配置 && printResultOk) || (echo -n yum源配置 && printResultErr)
}


#set ulimit
ulimit_config(){
       ver=`os_version`
		cat <<- EOF > /etc/security/limits.conf
			*           soft   nofile       65535
			*           hard   nofile       65535
			*           soft   nproc        65535
			*           hard   nproc        65535
		EOF
       if [[ $ver -eq 7 ]];then
		cat <<- EOF >/etc/security/limits.d/20-nproc.conf 
			*          soft    nproc     65535
			root       soft    nproc     unlimited
		EOF
       else
		cat <<- EOF >/etc/security/limits.d/90-nproc.conf 
			*          soft    nproc     65535
			root       soft    nproc     unlimited
		EOF
       fi
    [[ $? == 0 ]] && (echo -n ulimit配置 && printResultOk) || (echo -n ulimit配置 && printResultErr)
}
 
#set ldap client
ldap_config(){
     [ -f /etc/yum.repos.d/my.repo ] || wget -q -O /etc/yum.repos.d/my.repo http://my.inner.domain/xxx/repo/vhall/my.repo
     rpm --quiet -q my-ldapclinet
     if [ $? -eq 0 ];then
	 echo -n LDAP已经安装 && printResultIgnore && return 0
     fi
     yum clean all -q
     ver=`os_version`
     if [[ $ver -eq 7 ]];then
        yum -y install my-ldapclinet-1.0-1.el7* >/dev/null 2>&1
        [[ $? == 0 ]] && (echo -n LDAP安装 && printResultOk) || (echo -n LDAP安装 && printResultErr)
     else
        yum -y install my-ldapclinet* >/dev/null 2>&1
        [[ $? == 0 ]] && (echo -n LDAP安装 && printResultOk) || (echo -n LDAP安装 && printResultErr)
     fi
     sed  -i 's/ssl start_tls/#ssl start_tls/g' /etc/nslcd.conf
     sed  -i 's/ssl start_tls/#ssl start_tls/g' /etc/pam_ldap.conf
     service nslcd restart >/dev/null 2>&1
}
  
#set sysctl
sysctl_config(){
cp /etc/sysctl.conf /etc/sysctl.conf.ori.bak
cat <<- EOF > /etc/sysctl.conf
	fs.aio-max-nr = 1048576
	fs.file-max = 2048000
	kernel.core_uses_pid = 1
	kernel.msgmax = 655360
	kernel.msgmnb = 655360
	kernel.panic = 5
	kernel.shmall = 4294967296
	kernel.shmmax = 68719476736
	kernel.sysrq = 0
	net.core.netdev_max_backlog = 262144
	net.core.rmem_default = 8388608
	net.core.rmem_max = 16777216
	net.core.somaxconn = 65535
	net.core.wmem_default = 8388608
	net.core.wmem_max = 16777216
	net.ipv4.conf.all.accept_redirects = 0
	net.ipv4.conf.all.accept_source_route = 0
	net.ipv4.conf.all.arp_announce = 2
	net.ipv4.conf.all.rp_filter = 0
	net.ipv4.conf.all.send_redirects = 0
	net.ipv4.conf.default.accept_source_route = 0
	net.ipv4.conf.default.arp_announce = 2
	net.ipv4.conf.default.rp_filter = 0
	net.ipv4.conf.default.send_redirects = 0
	net.ipv4.conf.eth0.rp_filter = 0
	net.ipv4.conf.lo.arp_announce = 2
	net.ipv4.icmp_echo_ignore_broadcasts = 1
	net.ipv4.icmp_ignore_bogus_error_responses = 1
	net.ipv4.ip_forward = 1
	net.ipv4.ip_local_port_range = 1024 65535
	net.ipv4.neigh.default.gc_stale_time = 120
	net.ipv4.tcp_fin_timeout = 1
	net.ipv4.tcp_keepalive_time = 1800
	net.ipv4.tcp_max_orphans = 3276800
	net.ipv4.tcp_max_syn_backlog = 819200
	net.ipv4.tcp_max_tw_buckets = 180000
	net.ipv4.tcp_mem = 94500000 915000000 927000000
	net.ipv4.tcp_retrans_collapse = 0
	net.ipv4.tcp_rmem = 4096 65536 8388608
	net.ipv4.tcp_sack = 1
	net.ipv4.tcp_synack_retries = 1
	net.ipv4.tcp_syncookies = 1
	net.ipv4.tcp_syn_retries = 1
	net.ipv4.tcp_timestamps = 0
	net.ipv4.tcp_tw_recycle = 0
	net.ipv4.tcp_tw_reuse = 1
	net.ipv4.tcp_window_scaling = 1
	net.ipv4.tcp_wmem = 4096 65536 8388608
	vm.swappiness = 0
	vm.vfs_cache_pressure = 200
EOF
/sbin/sysctl -p >/dev/null 2>&1
        [[ $? == 0 ]] && (echo -n 系统参数优化 && printResultOk) || (echo -n 系统参数优化 && printResultErr)
}
  
#disable selinux
selinux_config(){
  status=`sestatus|awk '{print $3}'`
  if [[ ${status}x != "disabled"x ]];then
	sed -i '/SELINUX/s/enforcing/disabled/' /etc/selinux/config
	setenforce 0
        [[ $? == 0 ]] && (echo -n selinux关闭 && printResultOk && hint) || (echo -n selinux关闭 && printResultErr)
  else
        echo -n selinux已经关闭 && printResultIgnore
  fi 
}
 
##disable iptables
iptables_config(){
     ver=`os_version`
     if [[ $ver -eq 7 ]];then
	service firewalld status >/dev/null 2>&1
	if [ $? -ne 0 ];then
        	[[ $? == 0 ]] && (echo -n firewalld已经关闭 && printResultIgnore) && return 0
	fi	
	systemctl stop firewalld.service >/dev/null 2>&1
	systemctl disable firewalld.service >/dev/null 2>&1
        [[ $? == 0 ]] && (echo -n iptables关闭 && printResultOk) || (echo -n iptables关闭 && printResultErr)
     else
	service iptables status >/dev/null 2>&1
	if [ $? -ne 0 ];then
        	[[ $? == 0 ]] && (echo -n iptables已经关闭 && printResultIgnore) && return 0
	fi	
	service iptables stop >/dev/null 2>&1
        chkconfig --del iptables >/dev/null 2>&1
        [[ $? == 0 ]] && (echo -n iptables关闭 && printResultOk) || (echo -n iptables关闭 && printResultErr)
     fi
}

##set dns
dns_config(){
	ipAddr=`getIp eth0`
	ipFilter=${ipAddr%.*}

	delChattrFlag

	case $ipFilter in
	        $aliShaOnline)
	                cat <<- EOF > /etc/resolv.conf
				options timeout:1 attempts:1 rotate single-request-reopen
				nameserver 192.168.2.100
				nameserver 192.168.2.200
			EOF
			addChattrFlag
	                res=0
	                ;;
	        $aliHuaBei2cOnline)
	                cat <<- EOF > /etc/resolv.conf
				options timeout:1 attempts:1 rotate single-request-reopen
				nameserver 192.168.1.100
				nameserver 192.168.1.200
			EOF
			addChattrFlag
	                res=0
	                ;;
	        $aliHuaBei2eOnline)
	                cat <<- EOF > /etc/resolv.conf
				options timeout:1 attempts:1 rotate single-request-reopen
				nameserver 192.168.1.100
				nameserver 192.168.1.200
			EOF
			addChattrFlag
	                res=0
	                ;;
	        $aliHuaBei2eTest)
	                cat <<- EOF > /etc/resolv.conf
				options timeout:1 attempts:1 rotate single-request-reopen
				nameserver 10.10.2.100
			EOF
			addChattrFlag
	                res=0
	                ;;
	        $azure)
	                cat <<- EOF > /etc/resolv.conf
				options timeout:1 attempts:1 rotate single-request-reopen
				nameserver 192.168.6.100
				nameserver 192.168.6.200
			EOF
			addChattrFlag
	                res=0
	                ;;

	        *)
	                res=1
			;;
	esac

        [[ "$res" == 0 ]] && (echo -n DNS设置 && printResultOk) || (echo -n DNS设置 && printResultErr)
}

##set systemd
systemd_config(){
     ver=`os_version`
     if [[ $ver -eq 7 ]];then
		cat <<- EOF > /etc/systemd/system.conf
		[Manager]
		DefaultLimitCORE=infinity
		DefaultLimitNOFILE=65535
		DefaultLimitNPROC=65535
		EOF
		cat <<- EOF > /etc/systemd/user.conf
		[Manager]
		DefaultLimitCORE=infinity
		DefaultLimitNOFILE=65535
		DefaultLimitNPROC=65535
		EOF
        [[ $? == 0 ]] && (echo -n systemd服务设置 && printResultOk && hint) || (echo -n systemd服务设置 && printResultErr)
     fi
}
##set hosts.allow
allow_config(){
	cat <<- EOF > /etc/hosts.allow
	sshd: 127.0.0.1
	sshd: 192.168.0.0/255.255.0.0
	sshd: 172.16.0.0/255.255.0.0
	sshd: 10.0.0.0/255.0.0.0
	sshd: 1.2.3.4
	EOF
	cat <<- EOF >> /etc/hosts.deny
	sshd: all
	EOF
}
###auto cmdb
cmdb()
{
ipAddr=`getIp eth0`
ipFilter=${ipAddr%.*}
case $ipFilter in
        $aliShaOnline)
                echo "AliYun_EC_A_Prod" > /etc/location-info && cmdbClientDownload && res=0 || res=2
                ;;
        $aliHuaBei2cOnline)
                echo "AliYun_NC_C_Prod" > /etc/location-info && cmdbClientDownload && res=0 || res=2
                ;;
        $aliHuaBei2eOnline)
                echo "AliYun_NC_E_Prod" > /etc/location-info && cmdbClientDownload && res=0 || res=2
                ;;
        $aliHuaBei2eTest)
                echo "AliYun_NC_E_Test" > /etc/location-info && cmdbClientDownload && res=0 || res=2
                ;;
        $azure)
                echo "Azure" > /etc/location-info && cmdbClientDownload && res=0 || res=2
                ;;
        *)
                res=1
                ;;
esac
       [[ "$res" == 0 ]] && (echo -n cmdb客户端上报 && printResultOk) || (echo -n cmdb客户端上报 && printResultErr)
}

###ntp##
ntpd(){
	wget -q -O /etc/cron.d/ntp-aliyun.cron  http://my.inner.domain/xxx/ntp/ntp-aliyun.cron  >/dev/null 2>&1
	service ntpd stop >/dev/null 2>&1
     	ver=`os_version`
     	if [[ $ver -eq 7 ]];then
		systemctl disable ntpd >/dev/null 2>&1
		res=0
	else
		chkconfig --level 2345 ntpd off >/dev/null 2>&1
		res=0
	fi
       [[ "$res" == 0 ]] && (echo -n NTP设置 && printResultOk) || (echo -n NTP设置 && printResultErr)
}
###salt
saltClient()
{
	res=''
	ipAddr=`getIp eth0`
	hostName=`hostname`
	saltMasterIp=192.168.1.10
     	ver=`os_version`
     	if [[ $ver -eq 7 ]];then
	    if ! isInstalled salt-2017.7.2-1.el7 salt-minion-2017.7.2-1.el7 ;then
		wget -q -O /etc/yum.repos.d/my.repo http://my.inner.domain/xxx/repo/vhall/my.repo
		yum -q -y install salt salt-minion --disablerepo=salt6 >/dev/null 2>&1
		isInstalled salt-2017.7.2-1.el7 salt-minion-2017.7.2-1.el7 && res=0 || res=1
        	[[ "$res" == 0 ]] && (echo -n salt客户端安装 && printResultOk) || (echo -n salt客户端安装 && printResultErr)
	    else
        	echo -n salt客户端已经安装 && printResultIgnore
	    fi
	    if [[ $res -eq 0 ]];then
		cat <<- EOF > /etc/salt/minion
			master: $saltMasterIp
			id: ${hostName}-${ipAddr}
		EOF
		service salt-minion start >/dev/null 2>&1 && systemctl enable salt-minion >/dev/null 2>&1
        	[[ $? == 0 ]] && (echo -n salt客户端配置 && printResultOk) || (echo -n salt客户端配置 && printResultErr)
	    fi
	fi
     	if [[ $ver -eq 6 ]];then
	    if ! isInstalled salt-2017.7.2-1.el6 salt-minion-2017.7.2-1.el6;then
		wget -q -O /etc/yum.repos.d/my.repo http://my.inner.domain/xxx/repo/vhall/my.repo
		yum clean all >/dev/null 2>&1
		yum -q -t install salt salt-minion --disablerepo=salt7 >/dev/null 2>&1
		isInstalled salt-2017.7.2-1.el6 salt-minion-2017.7.2-1.el6 && res=0 || res=1
        	[[ "$res" == 0 ]] && (echo -n salt客户端安装 && printResultOk) || (echo -n salt客户端安装 && printResultErr)
	    else
        	echo -n salt客户端已经安装 && printResultIgnore
	    fi
	    if [[ $res -eq 0 ]];then
		cat <<- EOF > /etc/salt/minion
			master: $saltMasterIp
			id: ${hostName}-${ipAddr}
		EOF
		service salt-minion start >/dev/null 2>&1 && chkconfig --level 345 salt-minion on >/dev/null 2>&1
        	[[ $? == 0 ]] && (echo -n salt客户端配置 && printResultOk) || (echo -n salt客户端配置 && printResultErr)
	    fi
	fi
}
zabbixClient()
{
        ipAddr=`getIp eth0`
        ipFilter=${ipAddr%.*}

        case $ipFilter in
                $aliShaOnline)
			zabbixServer=192.168.2.1
                        ;;
                $aliHuaBei2cOnline)
			zabbixServer=192.168.1.1
                        ;;
                $aliHuaBei2eOnline)
			zabbixServer=192.168.1.1
                        ;;
                $aliHuaBei2eTest)
			zabbixServer=10.10.2.2
                        ;;
                $azure)
			zabbixServer=192.168.6.1
                        ;;
                *)
			res=1
	        	[[ "$res" == 0 ]] && (echo -n zabbix客户端设置 && printResultOk) || (echo -n zabbix客户端设置 && printResultErr)
			return 1
                        ;;
	esac

     	ver=`os_version`
     	if [[ $ver -eq 7 ]];then
		wget -q -O /etc/yum.repos.d/zabbix.repo  http://my.inner.domain/xxx/repo/zabbix/zabbix7.repo  >/dev/null 2>&1
		yum -y install zabbix-agent --disablerepo=epel 2>&1 >/dev/null
		cat <<- EOF > /etc/zabbix/zabbix_agentd.conf
			PidFile=/run/zabbix/zabbix_agentd.pid
			LogFile=/var/log/zabbix/zabbix_agent.log
			LogFileSize=0
			DebugLevel=2
			EnableRemoteCommands=0
			Server=127.0.0.1,$zabbixServer
			ListenPort=10050
			StartAgents=0
			ServerActive=$zabbixServer
			HostnameItem=system.hostname
			HostMetadataItem=system.uname
			RefreshActiveChecks=60
			AllowRoot=1
			Include=/etc/zabbix/zabbix_agentd.d/userparameter_enable
			UnsafeUserParameters=1	
		EOF
		[ -d /etc/zabbix/zabbix_agentd.d/userparameter_enable ] || mkdir /etc/zabbix/zabbix_agentd.d/userparameter_enable
		(service zabbix-agent start >/dev/null 2>&1) && (systemctl enable zabbix-agent >/dev/null 2>&1)
		res=0
	fi
     	if [[ $ver -eq 6 ]];then
		wget -O /etc/yum.repos.d/zabbix.repo  http://my.inner.domain/xxx/repo/zabbix/zabbix6.repo 2>&1 >/dev/null
		yum install zabbix22-agent --disablerepo=epel 2>&1 >/dev/null
		cat <<- EOF > /etc/zabbix/zabbix_agentd.conf
			PidFile=/run/zabbix/zabbix_agentd.pid
			LogFile=/var/log/zabbix/zabbix_agent.log
			LogFileSize=0
			DebugLevel=2
			EnableRemoteCommands=0
			Server=127.0.0.1,$zabbixServer
			ListenPort=10050
			StartAgents=0
			ServerActive=$zabbixServer
			HostnameItem=system.hostname
			HostMetadataItem=system.uname
			RefreshActiveChecks=60
			AllowRoot=1
			Include=/etc/zabbix/zabbix_agentd.d/userparameter_enable
			UnsafeUserParameters=1	
		EOF
		[ -d /etc/zabbix/zabbix_agentd.d/userparameter_enable ] || mkdir /etc/zabbix/zabbix_agentd.d/userparameter_enable
		(service zabbix-agent start >/dev/null 2>&1) && chkconfig --level 345 zabbix-agent on
		res=0
	fi
	        	[[ "$res" == 0 ]] && (echo -n zabbix客户端设置 && printResultOk) || (echo -n zabbix客户端设置 && printResultErr)
}
main(){
echo  '0)所有 1)yum 2)ulimit 3)sysctl 4)ldap 5)selinux 6)iptables 7)dns 8)systemd 9)hosts_allow 10)cmdb 11)ntpd 12)saltClient 13)zabbixClient 14)motd'
echo -n '输入服务数字:'
read num
case $num in
	"0")
		hostNameSet
		networkCheck
		yum_update
		ulimit_config
		sysctl_config
		ldap_config
		selinux_config
		iptables_config
		dns_config
		systemd_config
		allow_config
		cmdb
		ntpd
		saltClient
		zabbixClient
		motdSet
		;;
	"1")
		yum_update;;
	"2")
		ulimit_config;;
	"3")
		sysctl_config;;
	"4")
		ldap_config;;
	"5")
		selinux_config;;
	"6")
		iptables_config;;
	"7")
		dns_config;;
	"8")
		systemd_config;;
	"9")
		allow_config;;
	"10")
		cmdb;;
	"11")
		ntpd;;
	"12")
		saltClient;;
	"13")
		zabbixClient;;
	"14")
		motdSet;;	
	*)
		echo "请输入正确的数字~";;
esac
}
mainCommandLine(){
	case $1 in 
        "0")
                hostNameSet
                networkCheck
                yum_update
                ulimit_config
                sysctl_config
                ldap_config
                selinux_config
                iptables_config
                dns_config
                systemd_config
                allow_config
                cmdb
                ntpd
                saltClient
                zabbixClient
                motdSet
                ;;
        "1")
                yum_update;;
        "2")
                ulimit_config;;
        "3")
                sysctl_config;;
        "4")
                ldap_config;;
        "5")
                selinux_config;;
        "6")
                iptables_config;;
        "7")
                dns_config;;
        "8")
                systemd_config;;
        "9")
                allow_config;;
        "10")
                cmdb;;
        "11")
                ntpd;;
        "12")
                saltClient;;
        "13")
                zabbixClient;;
        "14")
                motdSet;;
        *)
                usage;;
esac
}

if [ $# -eq 0 ] ; then
	main
else
	mainCommandLine $1
fi
