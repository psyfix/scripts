#!/bin/bash
 
### CHECK RUNNING PRIVILEGE IS ROOT ###
if ! [ $(id -u) = 0 ]; 
then
        echo -e "This script needs to be run as root or with root privileges.\n" 
        echo -e "Try using sudo or log in as root."
        exit 1
fi

echo -e "starting..."
 
### OUTPUT SETUP ###

## VARIABLES
HOSTNAME=`hostname`
ENUM_NAME="enum-$HOSTNAME"
ENUM_FOLDER="/tmp/$ENUM_NAME"
ENUM_FILE="$ENUM_NAME.zip"

## CREATE FOLDERS FOR OUTPUT
mkdir "$ENUM_FOLDER"
cd /tmp
cd $ENUM_FOLDER
mkdir CIS-1.1-FILESYSTEM-CONFIGURATION
mkdir CIS-1.3-FILESYSTEM-INTEGRITY-CHECKING
mkdir CIS-1.6-MANDATORY-ACCESS-CONTROL
mkdir CIS-2.0-SERVICES
mkdir CIS-3.1-NETWORK-PARAMETERS
mkdir CIS-3.5-FIREWALL-CONFIGURATION
mkdir CIS-4.1-CONFIGURE-SYSTEM-ACCOUNTING
mkdir CIS-4.2-CONFIURE-LOGGING
mkdir CIS-5.1-CONFIGURE-CRON
mkdir CIS-5.2-SSH-SERVER-CONFIGURATION
mkdir CIS-5.3-CONFIGURE-PAM
mkdir CIS-5.4-USER-ACCOUNTS-AND-ENVIRONMENT
mkdir CIS-6.1-SYSTEM-FILE-PERMISSIONS
mkdir CIS-6.2-USER-AND-GROUP-SETTINGS

### CIS-1.1-FILESYSTEM-CONFIGURATION ###
echo -e "⚡GATHERING FILESYSTEM INFORMATION⚡"

## DISK DEVICES
if command -v lsblk &> /dev/null 2>&1
then
        lsblk -a > CIS-1.1-FILESYSTEM-CONFIGURATION/lsblk.txt 2>&1
else
        echo -e "lsblk command not found.\n"
fi

## DISK FILESYSTEM
if command -v df &> /dev/null 2>&1
then
        df -a -T -h > CIS-1.1-FILESYSTEM-CONFIGURATION/df.txt 2>&1
else
        echo -e "df command not found.\n"
fi

## DISK DEVICE MOUNT CONFIGURATION
if command -v cat &> /dev/null 2>&1
then
        cat /proc/mounts > CIS-1.1-FILESYSTEM-CONFIGURATION/mounts.txt 2>&1
else
        echo -e "cat command not found.\n"
fi

### CIS-1.3-FILESYSTEM-INTEGRITY-CHECKING ###

#AIDE 
if command -v dpkg-query &> /dev/null 2>&1
then
		dpkg-query -W -f='${Status}' aide 2>/dev/null | grep -c "ok installed" > CIS-1.3-FILESYSTEM-INTEGRITY-CHECKING/aide.txt 2>&1

		if ! [ $(cat CIS-1.3-FILESYSTEM-INTEGRITY-CHECKING/aide.txt) = 0 ] &> /dev/null 2>&1
		then
				echo -e "aide package installed.\n" > CIS-1.3-FILESYSTEM-INTEGRITY-CHECKING/aide.txt 2>&1
				
				##AUDIT AIDE CHECK AND TIMER
				if [[ -n $(find /etc/systemd/system/ -name 'aid*') ]] &> /dev/null 2>&1
				then 
						echo -e "=====================================\nLOOKING FOR AIDE SERVICE CHECK AND TIMER\n==================================="  >> CIS-1.3-FILESYSTEM-INTEGRITY-CHECKING/aide.txt 2>&1
						find /etc/systemd/system/ -name 'aid*' >> CIS-1.3-FILESYSTEM-INTEGRITY-CHECKING/aide.txt 2>&1
						systemctl -a | grep -w 'aidecheck' >> CIS-1.3-FILESYSTEM-INTEGRITY-CHECKING/aide.txt 2>&1
				
				else
						echo -e "=====================================\nLOOKING FOR AIDE SERVICE CHECK AND TIMER\n==================================="  >> CIS-1.3-FILESYSTEM-INTEGRITY-CHECKING/aide.txt 2>&1
						echo -e "aide service check and timer could not be found." >> CIS-1.3-FILESYSTEM-INTEGRITY-CHECKING/aide.txt 2>&1
				fi	
		else
				echo -e "aide package not installed.\n" > CIS-1.3-FILESYSTEM-INTEGRITY-CHECKING/aide.txt 2>&1
		fi
fi

echo -e "🔒COMPLETED!🔒\n"

### CIS-1.6-MANDATORY-ACCESS-CONTROL ###
echo -e "⚡GATHERING ACCESS CONTROL INFORMATION⚡"

## SELINUX

if command -v sestatus &> /dev/null 2>&1
then
		sestatus >> CIS-1.6-MANDATORY-ACCESS-CONTROL/SElinux.txt 2>&1

elif [[ -n $(find /etc/selinux/ -name 'config') ]] &> /dev/null 2>&1
then
		cat /etc/selinux/config >> CIS-1.6-MANDATORY-ACCESS-CONTROL/SElinux.txt 2>&1

else
		echo -e "selinux package not enabled.\n" > CIS-1.6-MANDATORY-ACCESS-CONTROL/SElinux.txt 2>&1
fi 

#APPARMOR

if command -v apparmor_status &> /dev/null 2>&1
then
		apparmor_status > CIS-1.6-MANDATORY-ACCESS-CONTROL/apparmor_status.txt 2>&1
else
		echo -e "apparmor package not installed.\n" > CIS-1.6-MANDATORY-ACCESS-CONTROL/apparmor_status.txt
fi  

echo -e "🔒COMPLETED!🔒\n"

### CIS-2.0-SERVICES ###
echo -e "⚡GATHERING SERVICE INFORMATION⚡"

## SYSTEMCTL
if command -v systemctl &> /dev/null 2>&1
then
        systemctl -a > CIS-2.0-SERVICES/systemctl-all.txt 2>&1
		systemctl -a > CIS-4.1-CONFIGURE-SYSTEM-ACCOUNTING/systemctl-all.txt 2>&1
		systemctl -a | grep 'avahi\|cups\|dhcpd\|slapd\|nfs\|rpcbind\|named\|ftpd\|http\|dovecot\|smb\|squid\|snmp\|rsync\|ypserv\|inetd\|telnet' | sort > CIS-2.0-SERVICES/systemctl-CIS-2.2.txt 2>&1
fi

## DATE
if command -v date &> /dev/null 2>&1
then
        date > CIS-2.0-SERVICES/date.txt 2>&1
else
        echo -e "date command not found.\n" > CIS-2.0-SERVICES/date.txt 2>&1
fi

## NTP
if command -v ntpstat &> /dev/null 2>&1
then
        ntpstat > CIS-2.0-SERVICES/ntp.txt 2>&1
		
		if [[ -f /etc/ntp.conf ]]
		then
				echo -e "=========================================="  >> CIS-2.0-SERVICES/ntp.txt 2>&1
				cat /etc/ntp.conf >> CIS-2.0-SERVICES/ntp.txt 2>&1
		fi
		
else
		echo -e "ntpstat command not found.\n" > CIS-2.0-SERVICES/ntp.txt 2>&1
		echo -e "ntp probably not installed, check the dpkg-all.txt and systemctl-all.txt files to verify." >> CIS-2.0-SERVICES/ntp.txt 2>&1
fi

## TIMEDATECTL
if command -v timedatectl &> /dev/null 2>&1
then
        timedatectl status > CIS-2.0-SERVICES/timedatectl.txt 2>&1
fi

## CHRONY
if command -v chronyc &> /dev/null 2>&1
then
        chronyc tracking > CIS-2.0-SERVICES/chrony.txt 2>&1
		chronyc sources >> CIS-2.0-SERVICES/chrony.txt 2>&1
fi

echo -e "🔒COMPLETED!🔒\n"

### CIS-3.1-NETWORK-PARAMETERS ###

## HOST ONLY
#if command -v sysctl &> /dev/null 2>&1
#then
#		sysctl net.ipv4.ip_forward >> CIS-3.1-NETWORK-PARAMETERS/host-only.txt 2>&1
#		sysctl net.ipv6.conf.all.forwarding >> CIS-3.1-NETWORK-PARAMETERS/host-only.txt 2>&1
#		sysctl net.ipv4.conf.all.send_redirects >> CIS-3.1-NETWORK-PARAMETERS/host-only.txt 2>&1
#		sysctl net.ipv4.conf.default.send_redirects >> CIS-3.1-NETWORK-PARAMETERS/host-only.txt 2>&1
#		
#		sysctl net.ipv4.conf.all.accept_source_route
#		sysctl net.ipv4.conf.default.accept_source_route
#		sysctl net.ipv6.conf.all.accept_source_route
#		sysctl net.ipv6.conf.default.accept_source_route
#		sysctl net.ipv4.conf.all.accept_redirects
#		sysctl net.ipv4.conf.default.accept_redirects
#		sysctl net.ipv6.conf.all.accept_redirects
#		sysctl net.ipv6.conf.default.accept_redirects
#
#else
#		echo -e "sysctl command not found." >> CIS-3.1-NETWORK-PARAMETERS/host-only.txt 2>&1
#
#fi

## HOST AND ROUTER

### CIS-3.5-FIREWALL-CONFIGURATION ###
echo -e "⚡GATHERING FIREWALL INFORMATION⚡"

## FIREWALL
if command -v iptables &> /dev/null 2>&1
then
        iptables -nL -v > CIS-3.5-FIREWALL-CONFIGURATION/iptables.txt 2>&1
else
        echo -e "iptables command not found.\n" > CIS-3.5-FIREWALL-CONFIGURATION/iptables.txt 2>&1
fi

if command -v ip6tables &> /dev/null 2>&1
then
        ip6tables -nL -v >> CIS-3.5-FIREWALL-CONFIGURATION/ip6tables.txt 2>&1
else
        echo -e "iptables command not found.\n" > CIS-3.5-FIREWALL-CONFIGURATION/ip6tables.txt 2>&1
fi

echo -e "🔒COMPLETED!🔒\n"

## EGRESS HTTP 
if command -v wget &> /dev/null 2>&1
then
		wget --spider https://www.google.com/ >> CIS-3.5-FIREWALL-CONFIGURATION/egress.txt 2>&1
		echo -e "================================================================================================" >> CIS-3.5-FIREWALL-CONFIGURATION/egress.txt 2>&1
		wget --spider https://www.helixsecurity.co.nz/ >> CIS-3.5-FIREWALL-CONFIGURATION/egress.txt 2>&1

elif command -v curl &> /dev/null 2>&1
then
		curl -i https://www.google.com > CIS-3.5-FIREWALL-CONFIGURATION/egress.txt 2>&1
		echo -e "================================================================================================" >> CIS-3.5-FIREWALL-CONFIGURATION/egress.txt 2>&1
		curl -i https://www.helixsecurity.co.nz/ >> CIS-3.5-FIREWALL-CONFIGURATION/egress.txt 2>&1
fi	

### CIS-4.1-CONFIGURE-SYSTEM-ACCOUNTING ###
echo -e "⚡GATHERING AUDIT INFORMATION⚡"

## AUDIT
if [[ -d /etc/audit ]]
then
		echo -e "Audit Configuration" > CIS-4.1-CONFIGURE-SYSTEM-ACCOUNTING/audit-conf.txt 2>&1
        cat /etc/audit/auditd.conf >> CIS-4.1-CONFIGURE-SYSTEM-ACCOUNTING/audit-conf.txt 2>&1
		
		if command -v auditctl &> /dev/null 2>&1
		then
				echo -e "\nAudit Rules" >> CIS-4.1-CONFIGURE-SYSTEM-ACCOUNTING/audit-rules.txt 2>&1
				auditctl -l >> CIS-4.1-CONFIGURE-SYSTEM-ACCOUNTING/audit-rules.txt 2>&1
		else
				cat /etc/audit/rules.d/audit.rules >> CIS-4.1-CONFIGURE-SYSTEM-ACCOUNTING/audit-rules.txt 2>&1
		fi
else
		echo -e "audit package not installed or configured.\n" >> CIS-4.1-CONFIGURE-SYSTEM-ACCOUNTING/audit-conf.txt 2>&1
		echo -e "audit probably not installed, check the dpkg-all.txt and systemctl-all.txt files to verify." >> CIS-4.1-CONFIGURE-SYSTEM-ACCOUNTING/audit-conf.txt 2>&1
fi

echo -e "🔒COMPLETED!🔒\n"

### CIS-4.2-CONFIURE-LOGGING ###
echo -e "⚡GATHERING LOGGING INFORMATION⚡"

## LOGGING
if [[ -f /etc/syslog.conf ]] || [[ -f /etc/rsyslog.conf ]] || [[ -f /etc/syslog-ng/syslog-ng.conf ]]
then
	##SYSLOG
		if [[ -f /etc/syslog.conf ]]
		then
				cat /etc/syslog.conf > CIS-4.2-CONFIURE-LOGGING/syslog.txt 2>&1
		fi

	##RSYSLOG
		if [[ -f /etc/rsyslog.conf ]]
		then
				cat /etc/rsyslog.conf > CIS-4.2-CONFIURE-LOGGING/rsyslog.txt 2>&1
		fi

	##SYSLOG-NG
		if [[ -f /etc/syslog-ng/syslog-ng.conf ]]
		then
				cat /etc/syslog-ng/syslog-ng.conf > CIS-4.2-CONFIURE-LOGGING/syslog-ng.txt 2>&1
		fi
else
		echo -e "syslog, rsyslog and syslog-ng packages not installed." > CIS-4.2-CONFIURE-LOGGING/syslog.txt 2>&1
fi

echo -e "🔒COMPLETED!🔒\n"

### CIS-5.1-CONFIGURE-CRON ###
echo -e "⚡GATHERING CRON INFORMATION⚡"

## CRON
if command -v crontab &> /dev/null 2>&1
then
		ls -la /etc/cron* >> CIS-5.1-CONFIGURE-CRON/crontab.txt 2>&1
		crontab -l >> CIS-5.1-CONFIGURE-CRON/crontab.txt 2>&1

else
		echo -e "crontab not installed." >> CIS-5.1-CONFIGURE-CRON/crontab.txt 2>&1
		
fi

echo -e "🔒COMPLETED!🔒\n"

### CIS-5.2-SSH-SERVER-CONFIGURATION ###
echo -e "⚡GATHERING SSH INFORMATION⚡"

### CIS-5.2-SSH-SERVER-BENCHMARK ###
echo -e "SSH Benchmark Standards to Check Against and Confirm Enabled:\nProtocol 2\nLogLevel VERBOSE or INFO\nX11Forwarding no\nMaxAuthTries < 4\nIgnoreRhosts yes\nHostbasedAuthentication no\nPermitRootLogin no\nPermitEmptyPasswords no\nPermitUserEnvironment no\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\nMACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256\nClientAliveInterval 300\nClientAliveCountMax 0\nLoginGraceTime 60\nUsePAM yes\nAllowTcpForwarding no\nMaxStartups 10:30:60\nMaxSessions 4\nSSH Permissions Benchmark:\nVerify Uid and Gid are both 0/root and 'Access' does not grant permissions to 'group' or 'other'." > CIS-5.2-SSH-SERVER-CONFIGURATION/ssh-benchmark.txt 2>&1

## SSH 
if [[ -d /etc/ssh ]]
then
		cat /etc/ssh/ssh_config > CIS-5.2-SSH-SERVER-CONFIGURATION/ssh.txt 2>&1
		cat /etc/ssh/sshd_config > CIS-5.2-SSH-SERVER-CONFIGURATION/sshd.txt 2>&1
		find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec stat {} \; > CIS-5.2-SSH-SERVER-CONFIGURATION/ssh-permissions-review.txt 2>&1
		stat /etc/ssh/sshd_config >> CIS-5.2-SSH-SERVER-CONFIGURATION/ssh-permissions-review.txt 2>&1
else
		echo -e "SSH not installed."  > CIS-5.2-SSH-SERVER-CONFIGURATION/ssh.txt 2>&1
fi

echo -e "🔒COMPLETED!🔒\n"

### CIS-5.3-CONFIGURE-PAM ###
echo -e "⚡GATHERING PAM INFORMATION⚡"

## PASSWORD POLICY
if command -v grep &> /dev/null 2>&1
then
		echo -e "======================================================================"   >> CIS-5.3-CONFIGURE-PAM/password-policy.txt 2>&1
		echo -e "PAM AND SECURITY MODULE" 												   >> CIS-5.3-CONFIGURE-PAM/password-policy.txt 2>&1
		echo -e "======================================================================"   >> CIS-5.3-CONFIGURE-PAM/password-policy.txt 2>&1
		grep -rw 'minlen\|dcredit\|ucredit\|ocredit\|lcredit\|minclass\|retry\|remember' /etc/pam.d/ /etc/security/ /etc/authselect/ >> CIS-5.3-CONFIGURE-PAM/password-policy.txt 2>&1 ##digit,uppercase,special,lower,complexity,retry
		echo -e "======================================================================"   >> CIS-5.3-CONFIGURE-PAM/password-policy.txt 2>&1
		echo -e "LOGIN.DEFS" 															   >> CIS-5.3-CONFIGURE-PAM/password-policy.txt 2>&1
		echo -e "======================================================================"   >> CIS-5.3-CONFIGURE-PAM/password-policy.txt 2>&1
		grep -rw 'PASS_MAX_DAYS\|PASS_MIN_DAYS\|PASS_WARN_AGE' /etc/login.defs >> CIS-5.3-CONFIGURE-PAM/password-policy.txt 2>&1
fi

## ACCOUNT LOCKOUT POLICY
if command -v grep &> /dev/null 2>&1
then
		grep -rw 'deny\|unlock_time' /etc/pam.d/ /etc/security/ /etc/authselect/ >> CIS-5.3-CONFIGURE-PAM/account-lockout-policy.txt 2>&1
fi

## PASSWORD HASHING
if command -v grep &> /dev/null 2>&1
then
		grep -rw 'crypt_style\|ENCRYPT_METHOD\|yescrypt\|sha512' /etc/pam.d/ /etc/libuser.conf >> CIS-5.3-CONFIGURE-PAM/password-hashing.txt 2>&1
fi

echo -e "🔒COMPLETED!🔒\n"

### CIS-5.4-USER-ACCOUNTS-AND-ENVIRONMENT ###
echo -e "⚡GATHERING USER ACCOUNT INFORMATION⚡"

## UMASK
if command -v umask &> /dev/null 2>&1
then
		umask >> CIS-5.4-USER-ACCOUNTS-AND-ENVIRONMENT/umask.txt 2>&1
fi

## TODO 5.6

echo -e "🔒COMPLETED!🔒\n"

### CIS-6.1-SYSTEM-FILE-PERMISSIONS ###
echo -e "⚡GATHERING FILE-PERMISSIONS INFORMATION⚡"

## SUID & GUID FILES
if command -v find &> /dev/null 2>&1
then
		find / -perm -g=s -type f -exec ls -la {} 2>/dev/null \; > CIS-6.1-SYSTEM-FILE-PERMISSIONS/guid-files.txt 2>&1
		find / -perm -u=s -type f -exec ls -la {} 2>/dev/null \; > CIS-6.1-SYSTEM-FILE-PERMISSIONS/suid-files.txt 2>&1	
fi

## WORLD WRITABLE FILES & FOLDERS
if command -v find &> /dev/null 2>&1
then
		find / \( -perm -o+w -perm -o+x \) -type d 2>/dev/null -exec ls -la \; > CIS-6.1-SYSTEM-FILE-PERMISSIONS/world-writable-folders.txt 2>&1
		find / \( -perm -o+w -perm -o+x \) -type f 2>/dev/null -exec ls -la \; > CIS-6.1-SYSTEM-FILE-PERMISSIONS/world-writable-files.txt 2>&1
		find / -perm -o+t -type d 2>/dev/null -exec ls -la \; > CIS-6.1-SYSTEM-FILE-PERMISSIONS/sticky-bit-folders.txt 2>&1
fi

echo -e "🔒COMPLETED!🔒\n"

### CIS-6.2-USER-AND-GROUP-SETTINGS ###
echo -e "⚡GATHERING USER AND GROUP SETTINGS INFORMATION⚡"


echo -e "🔒COMPLETED!🔒\n"

### ADDITIONAL INFORMATION COLLECTED ###
echo -e "⚡GATHERING ADDITIONAL SYSTEM INFORMATION⚡"

## COPY FILESYSTEM
tar cvfz etc.tar.gz --exclude=shadow --exclude=gshadow --exclude=gshadow- --exclude=ssh_host_*_key --exclude='ssl/private' /etc &> /dev/null 2>&1
#cp -R /var var
#cp -R /home home
#cp -R /opt opt

## NETSTAT 
if command -v netstat &> /dev/null 2>&1
then
        netstat -anp > netstat.txt 2>&1
else
        echo -e "netstat command not found.\n" > netstat.txt 2>&1
fi

## SS
if command -v ss &> /dev/null 2>&1
then
        ss -4tuln > ss.txt 2>&1
		ss -6tuln > ss6.txt 2>&1
else
        echo -e "ss command not found.\n" > ss.txt 2>&1
fi

## INTERFACE CONFIGURATION
if command -v ip &> /dev/null 2>&1
then
        ip a > ip.txt 2>&1

elif command -v ifconfig &> /dev/null 2>&1
then
        ifconfig -a > ifconfig.txt 2>&1

else
        echo -e "ip and ifconfig not found.\n" > ifconfig.txt 2>&1
fi

## UNAME
if command -v uname &> /dev/null 2>&1
then
        uname -a > uname.txt 2>&1
else
        echo -e "uname command not found.\n" > uname.txt 2>&1
fi

## LSB
if command -v lsb_release &> /dev/null 2>&1
then
        lsb_release -a > lsb_release.txt 2>&1
else
        echo -e "lsb_release command not found.\n" > lsb_release.txt 2>&1
fi

## PROCESSES
if command -v ps &> /dev/null 2>&1
then
        ps aux > ps.txt 2>&1
else
        echo -e "ps command not found.\n"
fi

## SNMP
if [[ -d /etc/snmp ]]
then
        cat /etc/snmp/snmpd.conf > snmp.txt 2>&1
		echo -e "\n" >> snmp.txt 2>&1
		cat /etc/snmp/snmp.conf >> snmp.txt 2>&1
else
		echo -e "SNMP not installed." > snmp.txt 2>&1
fi

##PACKAGE INFORMATION
if command -v dpkg &> /dev/null 2>&1
then
        dpkg --list > dpkg-all.txt 2>&1
		dpkg --list >> CIS-1.3-FILESYSTEM-INTEGRITY-CHECKING/dpkg-all.txt 2>&1
		dpkg --list >> CIS-1.6-MANDATORY-ACCESS-CONTROL/dpkg-all.txt 2>&1
		dpkg --list >> CIS-2.0-SERVICES/dpkg-all.txt 2>&1
		dpkg --list >> CIS-4.1-CONFIGURE-SYSTEM-ACCOUNTING/dpkg-all.txt 2>&1
		dpkg --list >> CIS-4.2-CONFIURE-LOGGING/dpkg-all.txt 2>&1

        egrep '( install | upgrade )' /var/log/dpkg.lo* > dpkg-latest.txt 2>&1
fi
echo -e "🔒COMPLETED!🔒\n"

### ZIP OUTPUT ###
cd /tmp
tar cvfz $ENUM_NAME.tar.gz $ENUM_NAME &> /dev/null 2>&1

echo -e "All results output into /tmp/$ENUM_NAME/ directory."
echo -e "All results are compressed here /tmp/$ENUM_NAME.tar.gz"