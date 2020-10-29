#!/bin/bash
#
# AppDynamics Cisco Technical Support report generator for Controller host
#
# https://serverfault.com/questions/103501/how-can-i-fully-log-all-bash-scripts-actions
APPDSYSTEMLOGFILE=/tmp/support_report_out.log
APPDSYSTEMXLOGFILE=/tmp/support_report_xtrace.log
exec 3>&1 4>&2
trap 'exec 2>&4 1>&3' 0 1 2 3 RETURN
exec 1>${APPDSYSTEMLOGFILE} 2>&1
exec 6>${APPDSYSTEMXLOGFILE}
BASH_XTRACEFD=6
set -x

VERSION=0.9
DAYS=3
ZIPREPORT=1
CGI=1
GETSYSTEM=1
GETVM=1
GETSTORAGE=1
GETOPENFILES=0
GETHARDWARE=1
GETMEMORY=1
GETSYSLOGS=1
GETNETCONF=1
GETNTPCONFIG=1
GETINIINFO=1
GETAPPD=1
GETNUMA=1
GETCONTROLLERLOGS=1
GETCONTROLLERMYSQLLOGS=1
GETCONTROLLERCONFIGS=1
GETLOAD=0
GETUSERLIMITS=1
GETCERTSINFO=1
GETMYSQLQUERIES=1
GETPROCESSES=1
GETTOP=1
GETFILELIST=1
GETSESTATUS=1
CLEANUP_WKDIR=1
ENCRYPT=0

ROOT_USER="root"
ROOT_GROUP="root"
MYSQL_PORT="3388"
SDATE=$(date +%F_%T | tr ":" '-')
INPROGRESS_FILE="/tmp/support_report.in_progress"
REPORTFILE="support-report_$(hostname)_${SDATE}.tar.gz"
mysql_password=""
HAVE_ACCESS_TO_CONTROLLER_DB=0
MYSQL_QUERY_TIMEOUT=5000

MAX_FILE_SIZE=15728640 # 15 MB
MAX_LINES=50000

function find_wkdir()
{
    # Find out what non-pseudo filesystems are supported by kernel
    for i in $(grep -v nodev /proc/filesystems); do
        # Filter only writable mounts
        mount | grep "$i" | grep rw >> /tmp/support_report.findtemp_mounts.$$
    done
    # Gather df information from writable mounts
    for i in $(awk '{print $3}' /tmp/support_report.findtemp_mounts.$$); do
        df -P | grep -e "$i$" >> /tmp/support_report.findtemp_df.$$
    done
    # Fallback default path if we can't write anywhere else
    local _wkdir_path=${HOME}
    # Going thru mounts list sorted by available space
    for i in $(sort -k 4 -rn /tmp/support_report.findtemp_df.$$ | awk '{print $6}'); do
        # we avoid writing to the root directory
        if [[ $i == "/" ]]; then
            continue
        fi
        # Write test
        touch $i/support_report_write_test 2> /dev/null
        rm $i/support_report_write_test 2> /dev/null
        if [ $? == 0 ]; then
            _wkdir_path=${i}
            break
        fi
    done
    WKDIR=${_wkdir_path}/support-report_$(hostname)_${SDATE}
}

# trap ctrl-c and clean before exit
function clean_after_yourself {
    if [ $CLEANUP_WKDIR -eq 1 ]; then
        rm -fr "${WKDIR}"
    fi

    rm "${INPROGRESS_FILE}"
    # we need to delete report log files as well
    rm /tmp/support_report*
}

trap ctrl_c INT
function ctrl_c() {
    clean_after_yourself
    exit
}

# simplified substitute for curl or wget, as these tools are not always present on server
# tested against locally running controller, with purpose to check status and simple API calls
# uses bash redirection hack
# example usage:   http_query  http://127.0.0.1/controller/rest/serverstatus
function http_query() {
	HOST=$(echo "$1" | sed -E 's/https?:\/\/([-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9]{1,6}\b):?([0-9]{1,4})?(.*)/\1/' )
# suppress sed printing all lines if no match for port
	PORT=$(echo "$1" | sed -E 's/https?:\/\/([-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9]{1,6}\b):?([0-9]{1,4})?(.*)/\2/' )	
	: ${PORT:=80}	# if empty, replace with default 80
	RESOURCE=$(echo "$1" | sed -E 's/https?:\/\/([-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9]{1,6}\b):?([0-9]{1,4})?(.*)/\3/' )
#{ echo "GET $RESOURCE HTTP/1.1"; echo "Host: $HOST"; echo;  } | $OPEN_PORT $HOST 8090 | sed '/<?xml/,$!d'
	exec 5<>/dev/tcp/$HOST/$PORT
	echo -e "GET $RESOURCE HTTP/1.1\r\nHost: $HOST\r\nConnection: close\r\n\r\n" >&5
	cat <&5 | sed '/<?xml/,$!d'
}

# we cannot assume linux flavor, and path for tools are sometimes different or tools are not present at all on customer's server
function assign_command()
{
	_cmd=$(which $1 2>/dev/null)
#	_cmd=$(which $1)
	_cmd=${_cmd:=warning "missing command: $1"}
	echo ${_cmd}
}

function prepare_paths()
{
VIRT_WHAT=$(assign_command virt_what)
LSB_RELEASE=$(assign_command lsb_release)
LSPCI=$(assign_command lspci)
LSCPU=$(assign_command lscpu)
IPTABLES=$(assign_command iptables)
VMWARE_CHECKVM=$(assign_command vmware-checkvm)
VMWARE_TOOLBOX_CMD=$(assign_command vmware-toolbox-cmd)
COPY_PRESERVE_COMMAND="cp -af"
SS=$(assign_command ss)
IP=$(assign_command ip)
LSMOD=$(assign_command lsmod)
LSOF=$(assign_command lsof)
LSBLK=$(assign_command lsblk)
NTPQ=$(assign_command ntpq)
IOSTAT=$(assign_command iostat)
VMSTAT=$(assign_command vmstat)
MPSTAT=$(assign_command mpstat)
TOP=$(assign_command top)
SAR=$(assign_command sar)
DMIDECODE=$(assign_command dmidecode)
TREE=$(assign_command tree)
OPENSSL=$(assign_command openssl)

# collection files
SYSTEM_CONFIGFILE=$WKDIR/11-system-config.txt
SYSTEM_PACKAGESFILE=$WKDIR/12-installed-software.txt
VM_CONFIGFILE=$WKDIR/13-vm-system.txt
STORAGE_CONFIGFILE=$WKDIR/14-storage.txt
OPENFILES=$WKDIR/15-openfiles.txt
HWCONF=$WKDIR/16-hw-config.txt
NETCONF=$WKDIR/17-net-config.txt
LOGS=$WKDIR/system-logs/
SYSCTL=$WKDIR/18-sysctl.txt
SLABINFO=$WKDIR/19-slabinfo.txt
SYSTREE=$WKDIR/20-systree.txt
CRONFILES=$WKDIR/21-cronfiles.txt
HOSTSFILE=$WKDIR/22-hosts
RESOLVFILE=$WKDIR/23-resolv.conf
ROOTCRON=$WKDIR/24-root-crontab.txt
NTPCONFIG=$WKDIR/25-ntp-config.txt
INITSCRIPTS=$WKDIR/26-initscripts.txt
PACKAGESFILE=$WKDIR/27-packages.txt
NUMAFILE=$WKDIR/28-numa.txt
PERFSTATS=$WKDIR/29-perfstats
APPD_JAVAINFO=$WKDIR/30-javainfo.txt
APPD_MYSQLINFO=$WKDIR/31-mysqlinfo.txt
APPD_INSTALL_USER_LIMITS=$WKDIR/32-install-user-limits.txt
APPD_CERTS=$WKDIR/33-controller-certs.txt
APPD_QUERIES=$WKDIR/34-controller-queries.txt
PROCESSES=$WKDIR/35-processes.txt
TOPREPORT=$WKDIR/36-top.txt
MEMINFO=$WKDIR/37-meminfo.txt
FILELIST=$WKDIR/38-filelist.xml
APPD_CONTROLLER_INFO=$WKDIR/39-controller-info.txt
SELINUX_INFO=$WKDIR/40-selinux-info.txt


# product specific paths and variables
APPD_SYSTEM_LOG_FILE="/tmp/support_report.log"
APPLOGS=$WKDIR/controller-logs
APPD_HOME="/opt/appd" #just default
APPD_CONTROLLER_HOME="/opt/appd/platform/product/controller"  #just default, this is re-evaluating later
APPD_CONTROLLER_JAVA_HOME=""
APPD_CONTROLLER_GLASSFISH_PID=
APPD_CONTROLLER_MYSQL_PID=
APPD_CONTROLLER_INSTALL_USER=""
APPD_CONTROLLER_INSTALL_GROUP=""
REPORT_PATH="" #TBD later
CONTROLLERLOGS=$WKDIR/controller-logs/
CONTROLLERMYSQLLOGS=$WKDIR/controller-mysql-logs/
CONTROLLERCONFIGS=$WKDIR/controller-configs/

ADDITIONAL_CONFIG_FILES=""
}

function log_variables()
{
  # clear password variable, we dont want to log it
  mysql_password=""
  set -o posix
  echo  "VARIABLES: " >> $APPDSYSTEMLOGFILE
  set >> $APPDSYSTEMLOGFILE
}

function message()
{
  echo "$@" >&3
  if [ $CGI -eq 1 ] && [ -f $APPDSYSTEMLOGFILE ]; then
    echo -ne "\n[REPORT] $(date) :: $@ \n" >> $APPDSYSTEMLOGFILE
  fi
}

function log_message()
{
  if [ $CGI -eq 1 ] && [ -f $APPDSYSTEMLOGFILE ]; then
    echo -ne "\n[REPORT] $(date) :: $@ \n" >> $APPDSYSTEMLOGFILE
  fi
}

function message_format()
# print message, with ANSI formatting given as 1st argument
{
  FORMAT=$1
  shift
  printf $FORMAT "$@" >&3
  if [ $CGI -eq 1 ] && [ -f $APPDSYSTEMLOGFILE ]; then
    echo -ne "\n[REPORT] $(date) :: $@ \n" >> $APPDSYSTEMLOGFILE 
  fi
}

function warning()
{
  message "WARNING: $@" >&3
  if [ $CGI -eq 1 ] && [ -f $APPDSYSTEMLOGFILE ]; then
    echo -ne "\n[REPORT] $(date) :: WARNING: $@ \n" >> $APPDSYSTEMLOGFILE 
  fi
  return 2
}

function log_warning()
{
  if [ $CGI -eq 1 ] && [ -f $APPDSYSTEMLOGFILE ]; then
    echo -ne "\n[REPORT] $(date) :: WARNING: $@ \n" >> $APPDSYSTEMLOGFILE 
  fi
  return 2
}

function err()
{
        message "ERROR: $1" >&3
        clean_after_yourself
        exit 1
}

function version()
{
   echo "$(basename $0) v$VERSION"
   exit 2
}
	
function reportheader()
{
        message "Generating report..."
        echo -e "$(basename $0) ver. $VERSION" >> $SYSTEM_CONFIGFILE
        echo -e "Host: $(hostname -f) - Compiled on $(date +%c) by $(whoami)\n" >> $SYSTEM_CONFIGFILE
}


function usage()
{
   FORMAT="%5s\t%-30s\n"
   message "Usage: $(basename $0) [ -vcpHlaz ] [ -d days of logs ]"
        message_format $FORMAT "-c" "Disable generating system configuration"
        message_format $FORMAT "-p" "Enable measuring system load/performance. It will be 720 of 5s samples. 1h in total."
        message_format $FORMAT "-H" "Disable generating hardware report"
        message_format $FORMAT "-l" "Disable gathering system logs"
        message_format $FORMAT "-a" "Disable gathering AppD logs"
        message_format $FORMAT "-d" "Number of days back of logs to retrieve (default is $DAYS days)"
        message_format $FORMAT "-z" "Do not zip report and leave it in /tmp"
        message_format $FORMAT "-e" "Encrypt output report archive with password"
        message_format $FORMAT "-v" "Version"
        exit 2
}

function zipreport()
{
    local _upper_dir=$(dirname $WKDIR)
    local _artifact_dir=$(basename $WKDIR)
    local _tar_archive=${REPORT_PATH}/${REPORTFILE}
    # zip -q9r $REPORT_PATH/$REPORTFILE $(basename $WKDIR)
    # zip could be preferable, easier for CU to review archive, but this tool is not always available.
    mv $APPDSYSTEMLOGFILE $WKDIR
    mv $APPDSYSTEMXLOGFILE $WKDIR
    # tar -C <dir> changes the directory before adding files
    tar -C $_upper_dir -cvzf $_tar_archive $_artifact_dir

    #TODO: should we chown old support_report_* files as well ?
    chown $APPD_CONTROLLER_INSTALL_USER:$APPD_CONTROLLER_INSTALL_GROUP ${_tar_archive}

    if [ -f $_tar_archive ]; then
        echo $REPORTFILE
    else
        err "Report $REPORTFILE  could not be created"
    fi
}

function encryptreport()
{
    #TODO: test this function
	message "Encrypting output file"
        $OPENSSL enc -e -aes-256-cbc -in ${REPORT_PATH}/${REPORTFILE} -out ${REPORT_PATH}/${REPORTFILE}.enc
        if [ $? -eq 1 ]; then
        	err "Report $REPORTFILE could not be encrypted, giving up"
        	exit 1
        else
        	rm -f ${REPORT_PATH}/${REPORTFILE}
        	return 0	
        fi
}

function getpackages()
{
        message "Building package list"
        echo linux flavour - $LINUX_FLAVOUR
        [[ ${LINUX_FLAVOUR} = "redhat" ]] && rpm -qa --queryformat "%{NAME} %{VERSION}\n" | sort  >> $PACKAGESFILE
        [[ ${LINUX_FLAVOUR} = "debian" ]] && dpkg-query -W -f='${Package} ${Version}\n' | sort  >> $PACKAGESFILE
        echo "done!"
}

function getlinuxflavour()
{
        _out=$(cat /etc/[A-Za-z]*[_-][rv]e[lr]* | uniq -u)
        [[ $(echo ${_out} | grep -i -E -e '(debian|ubuntu)' | wc -l ) -ge 1 ]] && LINUX_FLAVOUR=debian
        [[ $(echo ${_out} | grep -i -E -e '(rhel|redhat)'| wc -l ) -ge 1 ]] && LINUX_FLAVOUR=redhat
}

function getsystem()
{
        message "Building system configuration"
        echo "uptime: $(uptime)" >> $SYSTEM_CONFIGFILE
        echo -en "=================================\nOperating System\n---------------------------------\n" >> $SYSTEM_CONFIGFILE
        uname -a >> $SYSTEM_CONFIGFILE

 	[[ -f /etc/redhat-release ]] && $( head -1 /etc/redhat-release >> $SYSTEM_CONFIGFILE )
        [[ -f /etc/debian_version ]] && $( head -1 /etc/debian_version >> $SYSTEM_CONFIGFILE )
        
        cat /etc/*-release | uniq -u >> $SYSTEM_CONFIGFILE
        
        if [[ -x $LSB_RELEASE ]]; then
                $LSB_RELEASE -a >> $SYSTEM_CONFIGFILE
        fi
        
	echo -en "=================================\nLoaded Modules\n---------------------------------\n" >> $SYSTEM_CONFIGFILE
        $LSMOD >> $SYSTEM_CONFIGFILE

        if [ -f /etc/modules.conf ]; then
                cp -a /etc/modules.conf $WKDIR
        elif [ -f /etc/modprobe.conf ]; then
                cp -a /etc/modprobe.conf* $WKDIR
        fi

	echo -en "=================================\nLast logins\n---------------------------------\n" >> $SYSTEM_CONFIGFILE
	last -20 >> $SYSTEM_CONFIGFILE

	sysctl -A 2>/dev/null > $SYSCTL
       
	[ $ROOT_MODE -eq 1 ] && cat /proc/slabinfo > $SLABINFO
        
	[ -d /sys ] && ls -laR /sys 2>/dev/null > $SYSTREE
       
       
        # Get list of cron jobs
        ls -lr /etc/cron* > $CRONFILES
        
        [ $ROOT_MODE ] && [ -f /var/spool/cron/tabs/root ] && crontab -l > $ROOTCRON

        $COPY_PRESERVE_COMMAND /etc/hosts $HOSTSFILE
        # resolv.conf is often symlink
        cp /etc/resolv.conf  $RESOLVFILE
        ADDITIONAL_CONFIG_FILE_LIST=$(echo $ADDITIONAL_CONFIG_FILES | tr ',' ' ');
        for CONFIG_FILE in $ADDITIONAL_CONFIG_FILE_LIST; do
            [ -f $CONFIG_FILE ] && cp -a $CONFIG_FILE $WKDIR ;
        done
        
        getpackages
}        



function getvmware()
{
  message "Checking hypervisor"
    grep -q "^flags.*hypervisor" /proc/cpuinfo  && echo "Machine running under VM hypervisor." >> $VM_CONFIGFILE 
    if [[ $ROOT_MODE -eq 1 ]]; then
          echo  -en "\nVM Check: " >> $VM_CONFIGFILE
            VM=`${VIRT_WHAT} 2> /dev/null`
            [[ -z $VM && -x $(${VIRT_WHAT}) ]] && VM=$(${VIRT_WHAT})
            [[ -z $VM ]] && VM="Does not appear to be a VM"
            echo $VM  >> $VM_CONFIGFILE
    fi

    if [[ -x $VMWARE_CHECKVM ]]; then
	$VMWARE_CHECKVM >/dev/null
	if [ $? -eq 0 ]; then
	    [[ -x $VMWARE_CHECKVM ]] && $( $VMWARE_CHECKVM -h >> $VM_CONFIGFILE)
	    [[ -x $VMWARE_TOOLBOX_CMD ]] && (  (echo -en "Host time: ") && ( $VMWARE_TOOLBOX_CMD stat hosttime)) >> $VM_CONFIGFILE
	    (echo -en "This machine time: " && date ) >> $VM_CONFIGFILE
	    [[ -x $VMWARE_TOOLBOX_CMD ]] && (  (echo -en "CPU speed: ") && ( $VMWARE_TOOLBOX_CMD stat speed)) >> $VM_CONFIGFILE
	    [[ -x $VMWARE_TOOLBOX_CMD ]] && (  (echo -en "CPU res: ") && ( $VMWARE_TOOLBOX_CMD stat cpures)) >> $VM_CONFIGFILE
	    [[ -x $VMWARE_TOOLBOX_CMD ]] && (  (echo -en "CPU limit: ") && ( $VMWARE_TOOLBOX_CMD stat cpulimit)) >> $VM_CONFIGFILE
	    [[ -x $VMWARE_TOOLBOX_CMD ]] && (  (echo -en "MEM baloon: ") && ( $VMWARE_TOOLBOX_CMD stat balloon)) >> $VM_CONFIGFILE
	    [[ -x $VMWARE_TOOLBOX_CMD ]] && (  (echo -en "MEM swap: ") && ( $VMWARE_TOOLBOX_CMD stat swap)) >> $VM_CONFIGFILE
	    [[ -x $VMWARE_TOOLBOX_CMD ]] && (  (echo -en "MEM res: ") && ( $VMWARE_TOOLBOX_CMD stat memres)) >> $VM_CONFIGFILE
	    [[ -x $VMWARE_TOOLBOX_CMD ]] && (  (echo -en "MEM limit: ") && ( $VMWARE_TOOLBOX_CMD stat memlimit)) >> $VM_CONFIGFILE
	fi
    fi		    
}

function getmemory()
{
	message "Memory information"
        echo -e "\n----------\n free, human readable\n ----------" >> $MEMINFO
	free -h -w  >> $MEMINFO
        echo -e "\n----------\n free, machine friendly\n ----------" >> $MEMINFO
	free -w  >> $MEMINFO
        echo -e "\n----------\n swap partitions \n ----------" >> $MEMINFO
	cat /proc/swaps  >> $MEMINFO
        echo -e "\n----------\n /proc/sys/vm/swappiness \n ----------" >> $MEMINFO
	cat /proc/sys/vm/swappiness  >> $MEMINFO
        echo -e "\n----------\n MEM INFO\n ----------" >> $MEMINFO
        cat /proc/meminfo >> $MEMINFO
}

function gethardware()
{
        message "Copying hardware profile"
        echo -en "=================================\nSystem Specs\n---------------------------------\n" >> $HWCONF
        echo -e "\n---------------------------------\n Summarised CPU INFO\n ---------------------------------" >> $HWCONF
        ${LSCPU} >> $HWCONF
        echo -e "\n---------------------------------\n Detailed CPU INFO \n ---------------------------------" >> $HWCONF
        cat /proc/cpuinfo >> $HWCONF
        echo -e "\n---------- \n PCI BUS \n-----------" >> $HWCONF
        ${LSPCI} >> $HWCONF
        if [[ $ROOT_MODE -eq 1 ]]; then 
            ${DMIDECODE} >> $HWCONF
        else
           echo -e "\n---------- \ndmidecode \n-----------" >> $HWCONF
           sudo --non-interactive ${DMIDECODE} >> $HWCONF
           echo -en "\nScript has been not run by root, full hardware profile could not be collected." >> $HWCONF
           message "Script has been not run by root, full hardware profile could not be collected."
        fi
}

function getnetconf()
{
	message "Networking information"
        echo "=================================" >> $NETCONF
        echo "Network Configuration " >> $NETCONF
        echo -e "\n---------- Links Info ----------" >> $NETCONF
        $IP -o -s link >> $NETCONF
        echo -e "\n---------- Address Info ----------" >> $NETCONF
        $IP -o address >> $NETCONF
        echo -e "\n---------- Routes Info ----------" >> $NETCONF
        $IP -o route >> $NETCONF
        echo -e "\n---------- Rules Info ----------" >> $NETCONF
        $IP -o rule >> $NETCONF
        echo -e "\n---------- Network sockets ----------" >> $NETCONF
        $SS -anp >> $NETCONF

        if [[ $ROOT_MODE -eq 1 ]]; then 
        echo -e "\n---------- Network firewall configuration ----------" >> $NETCONF
            $IPTABLES -L -nv >> $NETCONF
        echo -e "\n---------- Network firewall configuration: NAT table ----------" >> $NETCONF
            $IPTABLES -L -t nat -nv >> $NETCONF
        fi
}


function getstorage()
{
	message "Storage information"
        echo -en "=================================\nStorage\n---------------------------------\n" >> $STORAGE_CONFIGFILE
        cat /proc/partitions >> $STORAGE_CONFIGFILE
        echo "----------------------------------" >> $STORAGE_CONFIGFILE
        echo -e "Device Partition table" >> $STORAGE_CONFIGFILE

# limited lskblk output for humans
        $LSBLK -fs -t >> $STORAGE_CONFIGFILE
        echo "----------------------------------" >> $STORAGE_CONFIGFILE
# lskblk output for machine parsing
# different lsblk versions have different possibilities, we want to catch all possible columns
        lsblk_columns=$($LSBLK  -h | grep '^  ' | awk '{print $1 }' |tr '\n' ',' | sed 's/,$//')
        $LSBLK -r -i -a --output ${lsblk_columns} >> $STORAGE_CONFIGFILE

        echo "----------------------------------" >> $STORAGE_CONFIGFILE
        df -Th >> $STORAGE_CONFIGFILE
        echo -en "=================================\nMounted File Systems\n---------------------------------\n" >> $STORAGE_CONFIGFILE
        cat /etc/mtab | egrep -i ^/dev | tr -s ' ' ';' | awk -F ';' '{ printf "%-15s %-15s %-10s %-20s %s %s\n",$1,$2,$3,$4,$5,$6 }' >> $STORAGE_CONFIGFILE
        cat /etc/mtab | egrep -iv ^/dev | tr -s ' ' ';' | awk -F ';' '{ printf "%-15s %-15s %-10s %-20s %s %s\n",$1,$2,$3,$4,$5,$6 }' | sort >> $STORAGE_CONFIGFILE
        echo -en "=================================\nConfigured File Systems\n---------------------------------\n" >> $STORAGE_CONFIGFILE
        cat /etc/fstab | egrep -i ^/dev | tr -s [:blank:] ';' | awk -F ';' '{ printf "%-15s %-15s %-10s %-20s %s %s\n",$1,$2,$3,$4,$5,$6 }' | sort >> $STORAGE_CONFIGFILE
        cat /etc/fstab | egrep -iv ^/dev | grep ^[^#] | tr -s [:blank:] ';' | awk -F ';' '{ printf "%-15s %-15s %-10s %-20s %s %s\n",$1,$2,$3,$4,$5,$6 }' | sort >> $STORAGE_CONFIGFILE

}

function getfilelist()
{
	message "AppD file list"
	# list of all APPD files + size , in XML format (machine parsable)
	$TREE -XDpugfah $APPD_HOME > $FILELIST
	echo tree result: $?
#	ls -lR $APPD_HOME > $FILELIST
}

 
function getopenfiles()
{
        # Print list of open files
        message_format "%s" "Reading open files. "
        $LSOF -n -b -w -P -X > $OPENFILES
        message "Done!"
}

function getsyslogs()
{
    message_format "%s"  "Copying system logs"
    [ -d $LOGS ] || mkdir $LOGS
    if [[ $ROOT_MODE -eq 1 ]]; then
        # Get system log for last $DAYS  day
        find /var/log -iname messages* -mtime -$DAYS -exec cp -a {} $LOGS \;
        find /var/log -iname boot.* -mtime -$DAYS -exec cp -a {} $LOGS \;
        find /var/log -iname kernel.log* -mtime -$DAYS -exec cp -a {} $LOGS \;
        find /var/log -iname ntp* -mtime -$DAYS -exec cp -a {} $LOGS \;
        find /var/log -iname cron* -mtime -$DAYS -exec cp -a {} $LOGS \;
        dmesg > $LOGS/dmesg

        if [ -d /var/log/sa ]; then
                mkdir $LOGS/sa
                find /var/log/sa -iregex '[a-z/]*sa\.*[0-9_]+' -exec $COPY_PRESERVE_COMMAND {} $LOGS/sa/ \;
        fi

        [ -f /var/log/wtmp ] && $COPY_PRESERVE_COMMAND /var/log/wtmp $LOGS/

        find /var/log -iname roothistory.log* -exec cp -a {} $LOGS \; 2>/dev/null
   else
   	message_format "%s"  " (very limited as you are not root). "
   	# as a non-root user we will be able to get only some crumbs. lets get just everything...
   	find /var/log -name "*.*" -mtime -$DAYS -exec cp -a {} $LOGS \; 2>/dev/null
        dmesg > $LOGS/dmesg
   fi   
   message "Done!"  
} 

function getntpconfig()
{
    message "Building ntpconfig"
    echo -e "\n---------- current system date and time ----------" >> $NTPCONFIG    
    date                 >> $NTPCONFIG
    echo -e "\n---------- current hardware date and time ----------" >> $NTPCONFIG    
    hwclock --get                 >> $NTPCONFIG    
    echo -e "\n---------- NTP peers ----------" >> $NTPCONFIG
    $NTPQ -n -c peers     >> $NTPCONFIG
    echo -e "\n---------- NTP associations ----------" >> $NTPCONFIG    
    $NTPQ -n -c as  >> $NTPCONFIG
    echo -e "\n---------- NTP sysinfo ----------" >> $NTPCONFIG    
    $NTPQ -n -c sysinfo  >> $NTPCONFIG
}
 
function getinitinfo()
{
	message "Init info"
        RUNLEVEL=$(runlevel | egrep -o [0-6abcs])
        echo "Current runlevel: $RUNLEVEL" > $INITSCRIPTS
        ls -l /etc/rc${RUNLEVEL}.d/* >> $INITSCRIPTS
}

function getprocesses()
{
	message_format "%s"  "Get processes. "
	ps xau > $PROCESSES
	message "Done!"
}

function gettop()
{
	message "Collecting TOP output"
	echo -e "\n---------- top report, CPU usage sorted ----------" >> $TOPREPORT
	$TOP -b -n3 -o +%CPU | head -35	 >> $TOPREPORT
	echo -e "\n---------- top report, MEM usage sorted ----------" >> $TOPREPORT
	$TOP -b -o +%MEM | head -35	 >> $TOPREPORT
	echo -e "\n---------- top report, TIME usage sorted ----------" >> $TOPREPORT
	$TOP -b -o TIME+ | head -35   >> $TOPREPORT
	
}


function subpath()
{
        echo "$1" |rev  | cut -d"/" -f $2- | rev
}

function appd_variables()
{
        APPD_CONTROLLER_GLASSFISH_PID=$(pgrep -f "s/glassfish.jar ")
        APPD_CONTROLLER_MYSQL_PID=$(pgrep -f "[d]b/bin/mysqld")

        if [[ -n $APPD_CONTROLLER_GLASSFISH_PID ]]; then
            # appserver running, piece of cake
            log_message "Found controller appserver PID $APPD_CONTROLLER_GLASSFISH_PID"
            APPD_HOME=$(subpath $(readlink /proc/$APPD_CONTROLLER_GLASSFISH_PID/cwd) 9)
            APPD_CONTROLLER_HOME=$(subpath $(readlink /proc/$APPD_CONTROLLER_GLASSFISH_PID/cwd) 6)
            APPD_CONTROLLER_JAVA_HOME=$(subpath $(readlink /proc/$APPD_CONTROLLER_GLASSFISH_PID/exe) 3)
            APPD_CONTROLLER_MYSQL_HOME="${APPD_CONTROLLER_HOME}/db"
        elif [[ -n $APPD_CONTROLLER_MYSQL_PID ]]; then
            # appserver not running, but we still got mysql, easy thing
            log_message "Found mysqld PID $APPD_CONTROLLER_MYSQL_PID"
            # in /proc/$pid/cmdline args are oddly separated with NULL (\x0)
            # first substitution cuts all from line beginning up to --basedir=
            # second one cuts everything after subsequent NULL separator
            # what's left is mysql basedir path, we're looking for
            APPD_CONTROLLER_MYSQL_HOME=$(sed -e 's/.*--basedir=//' -e 's/\x0--.*$//' /proc/$APPD_CONTROLLER_MYSQL_PID/cmdline)
            # if controller is not running, but mysqld is up we can figure out paths differently
            log_warning "Controller apparently not running, but mysql is still up"
            APPD_HOME=$(subpath $APPD_CONTROLLER_MYSQL_HOME 5)
            APPD_CONTROLLER_HOME=$(subpath $APPD_CONTROLLER_MYSQL_HOME 2)
            APPD_CONTROLLER_JAVA_HOME=$(find_controller_java_home)
        else
            # controller and DB are not running. so sad... let's try our best
            log_warning "Could not find running mysql server either controller instance!"
            # TODO: EC renames controller.sh to controller.sh-disabled on standby server
            local _dir=$(find / -name controller.sh -print -quit 2>/dev/null)
            #/appdynamics/platform/product/controller/bin/controller.sh
            APPD_HOME=$(subpath $_dir 6)
            APPD_CONTROLLER_HOME=$(subpath $_dir 3)
            APPD_CONTROLLER_JAVA_HOME=$(find_controller_java_home)
            APPD_CONTROLLER_MYSQL_HOME="${APPD_CONTROLLER_HOME}/db"
        fi

    APPD_CONTROLLER_INSTALL_USER=$(awk -F= '$1 ~ /^\s*user/ {print $2}' ${APPD_CONTROLLER_MYSQL_HOME}/db.cnf)
    if id -u $APPD_CONTROLLER_INSTALL_USER >/dev/null 2>&1; then
        APPD_CONTROLLER_INSTALL_GROUP=$(id -gn $APPD_CONTROLLER_INSTALL_USER)
    else
        APPD_CONTROLLER_INSTALL_USER=${ROOT_USER}
        APPD_CONTROLLER_INSTALL_GROUP=${ROOT_GROUP}
    fi
    APPD_DB_INSTALL_PORT=$(awk -F= '$1 ~ /^\s*port/ {print $2}' ${APPD_CONTROLLER_MYSQL_HOME}/db.cnf)
    if [ -z "${APPD_DB_INSTALL_PORT}" ] ; then
        APPD_DB_INSTALL_PORT=${MYSQL_PORT}
    fi

    APPD_CONTROLLER_MYSQL_DATADIR=$(find_controller_mysql_datadir)

    echo APPD_CONTROLLER_HOME $APPD_CONTROLLER_HOME
    echo APPD_CONTROLLER_JAVA_HOME $APPD_CONTROLLER_JAVA_HOME
    echo APPD_CONTROLLER_MYSQL_HOME $APPD_CONTROLLER_MYSQL_HOME
    echo APPD_CONTROLLER_MYSQL_DATADIR $APPD_CONTROLLER_MYSQL_DATADIR
    echo APPD_CONTROLLER_GLASSFISH_PID $APPD_CONTROLLER_GLASSFISH_PID
    echo APPD_CONTROLLER_MYSQL_PID $APPD_CONTROLLER_MYSQL_PID
    echo APPD_CONTROLLER_INSTALL_USER $APPD_CONTROLLER_INSTALL_USER
    echo APPD_DB_INSTALL_PORT $APPD_DB_INSTALL_PORT
}

#
# find java version used by appserver, based on asenv.conf
# the idea stolen from HA/lib/status.sh
#
function find_controller_java_home()
{
    if [ -f $APPD_CONTROLLER_HOME/appserver/glassfish/config/asenv.conf ]; then
        local _as_java=$(grep ^AS_JAVA= $APPD_CONTROLLER_HOME/appserver/glassfish/config/asenv.conf | awk -F\= '{ gsub(/"/,"",$2); print $2 }')
    else
        log_warning "Could not find java path in appserver config, but trying in jre/"
    fi

    local _product_home=$(subpath $APPD_CONTROLLER_HOME 2)
    # if no executable in AS_JAVA, tries jre/*
    # TODO: * evaluation uses numeric sort, can we do it better?
    local _path=""
    for _path in $_as_java $_product_home/jre/* ; do
        if [ -x $_path/bin/java ] ; then
            echo $_path
            break;
        fi
    done
}

#
# find mysql datadir path in db.cnf
#
#
function find_controller_mysql_datadir()
{
    local _db_conf=${APPD_CONTROLLER_HOME}/db/db.cnf
    if [ -f $_db_conf ]; then
        grep '^[[:space:]]*datadir=' $_db_conf| awk -F= '{print $2}'
    else
        log_warning "Could not find mysql datadir path in db.cnf"
    fi
}

function get_mysql_password()
{
    MYSQL="${APPD_CONTROLLER_MYSQL_HOME}/bin/mysql"

    if [ ! -x "$MYSQL" ]; then
        log_warning "Unable to find MySQL client in: ${APPD_CONTROLLER_MYSQL_HOME}"
    fi

    if [[ -z $mysql_password && -n $APPD_CONTROLLER_MYSQL_PID ]]; then
        message "MySQL root user password: "
        read -e -r -s -t15 mysql_password
        echo ""
    fi

    mysqlopts="-A -t -vvv --force --host=localhost --protocol=TCP --user=root "
    $MYSQL $mysqlopts --port=$APPD_DB_INSTALL_PORT --password=$mysql_password --batch -e 'status' 2>&1 >/dev/null
    if [ $? -eq 0 ]; then
        HAVE_ACCESS_TO_CONTROLLER_DB=1
    elif [ ! -z $mysql_password ]; then
        message "Unable to connect to the database - check your password or just hit enter to skip this step"
        unset mysql_password
        get_mysql_password
    fi
}


function get_mysql_data()
{
message "Collecting SQL queries"

if [ $HAVE_ACCESS_TO_CONTROLLER_DB -eq 0 ]; then
    echo -e "No access to controller DB, or MySQL process is not running." >> $APPD_QUERIES
    return 1
fi
echo -e "\n---------- Controller Profile Information ---------- " >> $APPD_QUERIES

while read query; do
  # redirect both stderr and stdout to capture exact error
  mysql_exec "$query" &>> $APPD_QUERIES
# WARNING! in queries use only single quotes and escape \ with \\
done <<EOF
select version() mysql_version;
select name, value from global_configuration_cluster where name in ('schema.version', 'performance.profile','appserver.mode','ha.controller.type');
select from_unixtime(ts_min*60), NOW(), count(distinct(node_id)), count(*) from metricdata_min where ts_min > (select max(ts_min) - 10 from metricdata_min) group by 1 order by 1;
select from_unixtime(ts_min*60), NOW(), count(distinct(node_id)), count(*) metric_count from metricdata_hour where ts_min > (select max(ts_min) - 10080 from metricdata_hour) group by 1 ORDER BY metric_count DESC LIMIT 10;
SELECT table_name FROM   information_schema.key_column_usage WHERE  table_name LIKE 'metricdata%' AND table_name != 'metricdata_min' AND table_name != 'metricdata_min_agg' AND column_name = 'ts_min' AND ordinal_position = 1;
select count(*) from eventdata_min;
select event_type,count(*) as count from eventdata_min group by event_type order by count desc;
SELECT table_name FROM information_schema.key_column_usage WHERE table_name LIKE 'metricdata%' AND table_name != 'metricdata_min' AND table_name != 'metricdata_min_agg' AND column_name = 'ts_min' AND ordinal_position = 1;
show table status from controller where Create_options='partitioned';
show table status from controller where Create_options != 'partitioned';
SELECT table_schema as 'Database', table_name AS 'Table', round(((data_length + index_length) / 1024 / 1024), 2) 'Size in MB' FROM information_schema.TABLES  ORDER BY (data_length + index_length) DESC;
select * from notification_config\\\G;
select name,value from global_configuration;
EOF
}

function mysql_exec()
{
  MYSQL="${APPD_CONTROLLER_MYSQL_HOME}/bin/mysql"
  mysqlopts="-A -t -vvv --force --host=localhost --protocol=TCP --user=root "
  $MYSQL $mysqlopts --init-command="SET SESSION MAX_EXECUTION_TIME=$MYSQL_QUERY_TIMEOUT;" --port=$APPD_DB_INSTALL_PORT --password=$mysql_password -e "$1" controller
}

function appd_getenvironment()
{
  message "Checking AppD environment"
    if [[ -n $APPD_CONTROLLER_GLASSFISH_PID ]]; then
        echo -e "\n---------- Controller Java PID ---------- " >> $APPD_JAVAINFO
        echo $APPD_CONTROLLER_GLASSFISH_PID >> $APPD_JAVAINFO
        echo -e "\n---------- Controller Java version ---------- " >> $APPD_JAVAINFO
		/proc/$APPD_CONTROLLER_GLASSFISH_PID/exe -version >> $APPD_JAVAINFO 2>&1
	 	echo -e "\n---------- Controller Java limits ---------- " >> $APPD_JAVAINFO
		cat /proc/$APPD_CONTROLLER_GLASSFISH_PID/limits >> $APPD_JAVAINFO
	 	echo -e "\n---------- Controller Java status ---------- " >> $APPD_JAVAINFO
		cat /proc/$APPD_CONTROLLER_GLASSFISH_PID/status >> $APPD_JAVAINFO
	 	echo -e "\n---------- Controller Java scheduler stats ---------- " >> $APPD_JAVAINFO
		 # use the source, Luke! 	kernel/sched/debug.c
		cat /proc/$APPD_CONTROLLER_GLASSFISH_PID/sched >> $APPD_JAVAINFO
	else
                echo -e "Controller Java process is not running." >> $APPD_JAVAINFO
	fi

	if [[ -n $APPD_CONTROLLER_MYSQL_PID ]]; then
	    echo -e "\n---------- Controller MySQL PID ---------- " >> $APPD_MYSQLINFO
        echo $APPD_CONTROLLER_MYSQL_PID >> $APPD_MYSQLINFO
        echo -e "\n---------- Controller MySQL version ---------- " >> $APPD_MYSQLINFO
		/proc/$APPD_CONTROLLER_MYSQL_PID/exe --version >> $APPD_MYSQLINFO 2>&1
	 	echo -e "\n---------- Controller MySQL limits ---------- " >> $APPD_MYSQLINFO
		cat /proc/$APPD_CONTROLLER_MYSQL_PID/limits >> $APPD_MYSQLINFO
	 	echo -e "\n---------- Controller MySQL status ---------- " >> $APPD_MYSQLINFO
		cat /proc/$APPD_CONTROLLER_MYSQL_PID/status >> $APPD_MYSQLINFO
	 	echo -e "\n---------- Controller MySQL scheduler stats ---------- " >> $APPD_MYSQLINFO
		 # use the source, Luke! 	kernel/sched/debug.c
		cat /proc/$APPD_CONTROLLER_MYSQL_PID/sched >> $APPD_MYSQLINFO
		
	else
                echo -e "Controller MySQL process is not running." >> $APPD_MYSQLINFO
	fi
		# some information about db size and files
		echo -e "\n---------- Controller MySQL files ---------- " >> $APPD_MYSQLINFO
		ls -la ${APPD_CONTROLLER_MYSQL_DATADIR} >> $APPD_MYSQLINFO
		echo -e "\n---------- Controller MySQL file size ---------- " >> $APPD_MYSQLINFO		
		du -hs ${APPD_CONTROLLER_MYSQL_DATADIR}/* >> $APPD_MYSQLINFO
}

function get_keystore_info()
{
	message "Controller Keystore content"
        echo -e "\n---------- Controller Keystore content ---------- " >> $APPD_CERTS
	$APPD_CONTROLLER_JAVA_HOME/bin/keytool -list --storepass "changeit" -rfc  -keystore ${APPD_CONTROLLER_HOME}/appserver/glassfish/domains/domain1/config/keystore.jks >> $APPD_CERTS
	$APPD_CONTROLLER_JAVA_HOME/bin/keytool -list --storepass "changeit" -v  -keystore ${APPD_CONTROLLER_HOME}/appserver/glassfish/domains/domain1/config/keystore.jks >> $APPD_CERTS
}

function getnumastats()
{
	message "Numa stats"
 	echo -e "\n---------- Numa inventory of available nodes on the system ---------- " >> $NUMAFILE
	numactl -H >> $NUMAFILE
 	echo -e "\n---------- per-NUMA-node memory statistics for operating system ---------- " >> $NUMAFILE
	numastat >> $NUMAFILE
	echo -e "\n---------- per-NUMA-node memory statistics for java and mysql processes ---------- " >> $NUMAFILE
	numastat -czmns java mysql  >> $NUMAFILE
}

function checkfilesize(){
    filename=$1
    allowedsize=$2
    if [ $(stat -f%z $filename) -ge $allowedsize ]
    then
         true
    else
        false
    fi
}


function getcontrollerlogs()
{
	message "Controller logs"
        [ -d $CONTROLLERLOGS ] || mkdir $CONTROLLERLOGS
        
    for f in $(find $APPD_CONTROLLER_HOME/logs -name "*.log" ! -path "$APPD_CONTROLLER_HOME/logs/support-report/*" -type f)
    do
        if checkfilesize $f $MAX_FILE_SIZE
            then
                tail -n $MAX_LINES $f > "$CONTROLLERLOGS/$(echo $f | awk 'BEGIN { FS = "/" } ; { print $NF }')"
            else
                cp $f $CONTROLLERLOGS
        fi
    done
    
    message "Collecting rotating logs form $DAYS days"
    find $APPD_CONTROLLER_HOME/logs -name "*.log_*" ! -path "$APPD_CONTROLLER_HOME/logs/support-report/*" -mtime -$DAYS -exec cp -a {} $CONTROLLERLOGS \;
}

function getmysqlcontrollselogs()
{
	message "Mysql Controller logs"
#/appdynamics/platform/product/controller/db/logs/
        [ -d $CONTROLLERMYSQLLOGS ] || mkdir $CONTROLLERMYSQLLOGS
        find $APPD_CONTROLLER_HOME/db/logs/ -name "*.*" -mtime -$DAYS -exec cp -a {} $CONTROLLERMYSQLLOGS \;
}

function getcontrollerconfigs()
{
	message "Controller configs"
#/appdynamics/platform/product/controller/appserver/glassfish/domains/domain1/config
        [ -d $CONTROLLERCONFIGS ] || mkdir $CONTROLLERCONFIGS
	find $APPD_CONTROLLER_HOME/appserver/glassfish/domains/domain1/config -name "*.*" -exec cp -a {} $CONTROLLERCONFIGS \;
	find $APPD_CONTROLLER_HOME/db/ -name "*.cnf" -exec cp -a {} $CONTROLLERCONFIGS \;
	find $APPD_CONTROLLER_HOME/ -name "*.lic" -exec cp -a {} $CONTROLLERCONFIGS \;
}


function getcontrollerinfo()
{
	message "Controller related information"
	echo -e "\n---------- Controller version information from README file ---------- " >> $APPD_CONTROLLER_INFO
	cat $APPD_CONTROLLER_HOME/README.txt >> $APPD_CONTROLLER_INFO

	echo -e "\n---------- Controller version information from MANIFEST file ---------- " >> $APPD_CONTROLLER_INFO
	cat $APPD_CONTROLLER_HOME/appserver/glassfish/domains/domain1/applications/controller/META-INF/MANIFEST.MF >> $APPD_CONTROLLER_INFO

	echo -e "\n---------- Controller SCHEMA information from database ---------- " >> $APPD_CONTROLLER_INFO
	if [ $HAVE_ACCESS_TO_CONTROLLER_DB -eq 1 ]
		then
			$MYSQL $mysqlopts --port=$APPD_DB_INSTALL_PORT --password=$mysql_password >> $APPD_CONTROLLER_INFO <<EOF
				use controller;
				select name, value from global_configuration_cluster where name in ('schema.version', 'performance.profile','appserver.mode','ha.controller.type');
EOF
	else
			echo -e "\n Not available. No access to DB. " >> $APPD_CONTROLLER_INFO
	fi

	echo -e "\n---------- Controller server status from API ---------- " >> $APPD_CONTROLLER_INFO
	http_query http://127.0.0.1:8090/controller/rest/serverstatus >> $APPD_CONTROLLER_INFO
}


# strings platform/mysql/data/platform_admin/configuration_store.ibd | grep "JobcontrollerRootUserPassword" | tail -1 | awk -F'"' '{print $2}'^C
function getmysqlcontrollerpass()
{
	# root password for controller can be stored in few places. we will try to find it.
	# EC db
	[[ -f $APPD_HOME/platform/mysql/data/platform_admin/configuration_store.ibd ]] && pass=$(strings $APPD_HOME/platform/mysql/data/platform_admin/configuration_store.ibd | grep "JobcontrollerRootUserPassword" | tail -1 | awk -F'"' '{print $2}')
	echo $pass
}


function getloadstats()
{
                message "Measuring basic system load. It will take some time, more like an hour... Time for coffe break. "
#	        echo -en "=================================\nDisk IO usage\n---------------------------------\n" >> $PERFSTATS
                nohup $IOSTAT -myxd 5 720 >> $PERFSTATS-iostat.txt &
#	        echo -en "=================================\nCPU and interrupts usage\n---------------------------------\n" >> $PERFSTATS
                nohup $MPSTAT -A 5 720 >> $PERFSTATS-mpstat.txt &
#                echo -en "=================================\nMemory Utilization\n---------------------------------\n" >> $PERFSTATS
                nohup $VMSTAT -t -n -a 5 720 >> $PERFSTATS-vmstat.txt &
#                echo -en "=================================\nNetwork Utilization\n---------------------------------\n" >> $PERFSTATS
                nohup $SAR -n DEV 5 720 >> $PERFSTATS-sar-net.txt &
                message "done!"
}

function getinstalluserlimits()
{
    message "Fetching install user ulimits"
    echo -en "=================================\nInstall User\n---------------------------------\n" >> $APPD_INSTALL_USER_LIMITS
    echo $APPD_CONTROLLER_INSTALL_USER >> $APPD_INSTALL_USER_LIMITS
    echo -en "=================================\nulimits\n---------------------------------\n" >> $APPD_INSTALL_USER_LIMITS
    if [[ $ROOT_MODE -eq 1 ]]; then
        sudo --non-interactive su - $APPD_CONTROLLER_INSTALL_USER -c "ulimit -a" >> $APPD_INSTALL_USER_LIMITS
    else
        ulimit -a >> $APPD_INSTALL_USER_LIMITS
    fi
}

function prepare_wkdir()
{
    if [ ! -d $WKDIR ]; then
        mkdir -p $WKDIR
    fi
    [ -d $WKDIR ] || err "Could not create working directory $WKDIR"
    cd $WKDIR
}

#
# Run after appd_variables()
#
function prepare_report_path()
{
    REPORT_PATH=${APPD_CONTROLLER_HOME}/logs/support-report
    if [ ! -d $REPORT_PATH ]; then
        mkdir -p $REPORT_PATH
        chown ${APPD_CONTROLLER_INSTALL_USER}:${APPD_CONTROLLER_INSTALL_GROUP} ${REPORT_PATH}
    fi
    [ -d $REPORT_PATH ] || err "Could not create report directory $REPORT_PATH"
}

function check_user()
{
    RUN_AS=$(whoami)
    if [ "$RUN_AS" == "$ROOT_USER" ]; then
        ROOT_MODE=1
    else
        ROOT_MODE=0
        warning  "You should run this script as root. Only limited information will be available in report."
        if [ "$RUN_AS" != "$APPD_CONTROLLER_INSTALL_USER" ]; then
            err "You must run this tool as root or as the same user who is running appd processes"
        fi
    fi
}

function get_selinux_info()
{
    message "Getting selinux config"
    echo -en "=================================\nsestatus\n---------------------------------\n" >> $SELINUX_INFO
    echo -e "$(sestatus)" >> $SELINUX_INFO
    echo >> $SELINUX_INFO
    echo -en "=================================\n/etc/selinux/config\n---------------------------------\n" >> $SELINUX_INFO
    echo -e "$(cat /etc/selinux/config)\n" >> $SELINUX_INFO
    echo -en "=================================\n/etc/sestatus.conf\n---------------------------------\n" >> $SELINUX_INFO
    echo -e "$(cat /etc/sestatus.conf)\n" >> $SELINUX_INFO
}

#########################
# START MAIN
#########################

while getopts "aceflpwvzd:P:" opt; do
        case $opt in
                a  )    GETCONTROLLERLOGS=0
                                ;;
                c  )    GETCONFIG=0
                                ;;
                e  )    ENCRYPT=1
                                ;;
                f  )    GETOPENFILES=1
                		;;
                p  )    GETLOAD=1
                                ;;
                w  )    GETHARDWARE=0
                                ;;
                l  )    GETSYSLOGS=0
                                ;;
                z  )    ZIPREPORT=0
                                ;;
                d  )    DAYS=$OPTARG
                                ;;
                P)
                        mysql_password=$OPTARG
                                ;;
                v  )    version
                                ;;
                \? )    usage
                                ;;
        esac
done




# dont allow to run more than one report collection at once
if [ -f $INPROGRESS_FILE ]
then
    err "Generation of support report in progress. Exiting.";
    exit 1;
fi
touch $INPROGRESS_FILE;
echo $REPORTFILE > $INPROGRESS_FILE;


# Setup work environment
find_wkdir
prepare_wkdir
prepare_paths
getlinuxflavour
appd_variables
# we need to know appd user already
check_user
prepare_report_path
get_mysql_password
reportheader


# collect reports
[ $GETSYSTEM -eq 1 ] && getsystem
[ $GETVM -eq 1 ] && getvmware
[ $GETHARDWARE -eq 1 ] && gethardware
[ $GETMEMORY -eq 1 ] && getmemory
[ $GETSTORAGE -eq 1 ] && getstorage
[ $GETOPENFILES -eq 1 ] && getopenfiles
[ $GETSYSLOGS -eq 1 ] && getsyslogs
[ $GETNETCONF -eq 1 ] && getnetconf
[ $GETNTPCONFIG -eq 1 ] && getntpconfig
[ $GETINIINFO -eq 1 ] && getinitinfo
[ $GETAPPD -eq 1 ] && appd_getenvironment
[ $GETNUMA -eq 1 ] && getnumastats
[ $GETCONTROLLERLOGS -eq 1 ] && getcontrollerlogs
[ $GETCONTROLLERMYSQLLOGS -eq 1 ] && getmysqlcontrollselogs
[ $GETCONTROLLERCONFIGS -eq 1 ] && getcontrollerconfigs
[ $GETLOAD -eq  1 ] && getloadstats
[ $GETUSERLIMITS -eq  1 ] && getinstalluserlimits
[ $GETCERTSINFO -eq  1 ] && get_keystore_info
[ $GETMYSQLQUERIES -eq  1 ] && get_mysql_data
[ $GETPROCESSES -eq  1 ] && getprocesses
[ $GETTOP -eq  1 ] && gettop
[ $GETFILELIST -eq 1 ] && getfilelist
[ $GETSESTATUS -eq 1 ] && get_selinux_info
getcontrollerinfo

# Make all report files readable
chmod -R a+rX $WKDIR

if [ -f $INPROGRESS_FILE ]
then
    rm -f $INPROGRESS_FILE;
fi

# iostat and family are running in background, output is needed before we pack the archive
for job in `jobs -p`
do
message "waiting for job $job to finish..."
    wait $job 
done

log_variables
if [ $ZIPREPORT -eq 1 ]; then
    message -n "Creating report archive... "
    REPORT=$(zipreport)
    message "Done "
    ARTEFACT=${REPORTFILE}
    if [ $ENCRYPT -eq 1 ]; then
        message -n "Encrypting archive... "
        encryptreport
        if [ $? -eq 0 ]; then    
            ARTEFACT=${REPORTFILE}.enc
        fi
    fi
    message
    message "The support-report can be downloaded from"
    message "   ${REPORT_PATH}/${ARTEFACT}"

    message "You will be directed where to submit this report by your technical support contact."
else
    CLEANUP_WKDIR=0
    message -e "\nReport located in $WKDIR"
fi

clean_after_yourself

exit 0

#########################
# END MAIN
#########################
