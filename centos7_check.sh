#!/bin/bash
#version v1.0 by Big&&Bird
#Linux操作系统安全基线检查---centos7
cat <<EOF
************************************************
linux安全配置检查脚本
    1.输出结果在/tmp/check/目录下查看
    2.检查范围及检查项（共计4大类，33项）
*用户账号配置
    [1]检查是否存在空口令账户
    [2]密码复杂度检查
    [3]检查是否存在除root之外UID为0的用户
    [4]检查密码的生存期
*SSH服务配置
    [5]sshd强制使用V2安全协议
	[6]禁止ssh空密码用户登录
	[7]检查ssh MaxAuthTries设置为3到6之间
	[8]检查ssh空闲超时退出时间
	[9]检查ssh LogLevel级别
*重要文件权限检查
    [10]检查/etc目录下重要文件权限
*日志审计
	[11]检查用户认证服务配置
	[12]检查其他服务配置
	[13]检查rsyslog是否开启
************************************************
EOF

if [ ! -d /tmp/check ];then
    mkdir /tmp/check
else
    echo dir exist > /dev/null
fi

echo "begin..."

str=`/sbin/ifconfig -a | grep inet | grep 192.168.110.130 | awk '{print $2}'` 
str1=`date +%Y%m%d%H%M%S`_"$str"
str2="/tmp/check/${str1}_out.txt"

echo "-------------------*****用户账号配置*****-------------------" >>  $str2
echo "[1]检查是否存在空口令账户" >> $str2
if [ `awk -F: '($2 == "") {print $1}' /etc/shadow`];then
    echo "存在空口令账户" >> $str2
else
    echo  "不存在空口令账户" >> $str2
fi
echo "--------------------------------" >> $str2

echo "[2]密码复杂度检查" >> $str2
if [ -e /etc/security/pwquality.conf ];then
    pwminlen=`cat /etc/security/pwquality.conf | grep minlen | awk '{print $4}'`
    pwminclass=`cat /etc/security/pwquality.conf | grep minclass | awk '{print $4}'`
    echo "密码安全策略要求最小长度为${pwminlen}个" >> $str2
    echo "密码安全策略要求大小写字符、数字、特殊符号至少要包含${pwminclass}类" >> $str2
else
    echo "/etc/security/pwquality.conf不存在" >> $str2
fi
echo "-----------------------------" >> $str2

echo "[3]检查是否存在除root之外UID为0的用户" >> $str2
uids=`awk -F: 'NR!=1{print $3}' /etc/passwd`
flag=0
for i in $uids:
do
    if [ "$i" = 0 ];then
        echo "存在除root之外uid为0的用户，不符合要求!" >> $str2
        break
    else
        flag=1
    fi
done
if [ "$flag" = 1 ];then
    echo "不存在除root之外uid为0的用户，符合要求!"  >> $str2
fi
echo "-------------------------------" >> $str2

echo "[4]检查密码的生存期" >> $str2
if [ -e /etc/login.defs ];then
    passwdmax=`cat /etc/login.defs | grep PASS_MAX_DAYS | sed -n '2p' | awk '{print $2}'`
    passwdmin=`cat /etc/login.defs | grep PASS_MIN_DAYS | sed -n '2p' | awk '{print $2}'`
    passwdlen=`cat /etc/login.defs | grep PASS_MIN_LEN | sed -n '2p' | awk '{print $2}'`
    passwdwarn=`cat /etc/login.defs | grep PASS_WARN_AGE | sed -n '2p' | awk '{print $2}'`
    
    echo "密码最长过期天数为${passwdmax}天"  >> $str2
    echo "密码最小过期天数为${passwdmin}天"  >> $str2
    echo "密码最小长度为${passwdlen}"        >> $str2
    echo "密码过期警告天数为${passwdwarn}天"  >> $str2
else
    echo "不存在/etc/login.defs文件"   >> $str2
fi
echo "--------------------------------" >> $str2
echo 用户账号配置检查完毕

echo "" >> $str2
echo "-------------------*****SSH服务配置*****-------------------" >> $str2
echo "[5]sshd强制使用V2安全协议" >> $str2
ssh_protocol=`cat /etc/ssh/sshd_config  | grep  -v "#" | grep Protocol | awk '{print $2}'`
if [ "$ssh_protocol" = 2 ];then
    echo "sshd使用了V2安全协议"  >> $str2
else
    echo "sshd没有使用V2安全协议" >> $str2
fi
echo "--------------------------------" >> $str2

echo "[6]禁止ssh空密码用户登录" >> $str2
ssh_emptypw=`cat /etc/ssh/sshd_config  | grep  -v "#" | grep PermitEmptyPasswords | awk  '{print $2}'`
if [ "$ssh_emptypw" = "yes" ];then
    echo "ssh已经禁止了空密码用户登录" >> $str2
else
    echo "ssh允许空密码用户登录" >> $str2
fi
echo "--------------------------------" >> $str2

echo "[7]检查ssh MaxAuthTries设置为3到6之间" >> $str2
ssh_maxauthtries=`cat /etc/ssh/sshd_config | grep MaxAuthTries  | grep -v ^# | awk '{print $2}'`
if [ $ssh_maxauthtries ];then
    ssh_maxauthtries2=`cat /etc/ssh/sshd_config | grep MaxAuthTries  | awk '{print $2}'`
    if [ "$ssh_maxauthtries2" -gt 6 ];then
        echo "ssh最大尝试登录次数为${ssh_maxauthtries2},不符合要求，建议设置为5" >> $str2
    elif [ "$ssh_maxauthtries2" -ge 3 ] && [ "$ssh_maxauthtries2" -le 6 ];then
        echo "ssh最大尝试登录次数为${ssh_maxauthtries2},符合要求" >> $str2
    else
        echo "ssh最大尝试登录次数为${ssh_maxauthtries2},不符合要求，建议设置为5" >> $str2
    fi
else
    echo "请取消MaxAuthTries前的注释!" >> $str2
fi
echo "----------------------------------" >> $str2

echo "[8]检查ssh空闲超时退出时间" >> $str2
ssh_interval=`cat /etc/ssh/sshd_config | grep -v ^# | grep ClientAliveInterval | awk '{print $2}'`
ssh_countmax=`cat /etc/ssh/sshd_config | grep -v ^# | grep ClientAliveCountMax | awk '{print $2}'`
if [[ $ssh_interval && $ssh_countmax ]];then
    ssh_interval2=`cat /etc/ssh/sshd_config | grep ClientAliveInterval | awk '{print $2}'`
    ssh_countmax2=`cat /etc/ssh/sshd_config | grep ClientAliveCountMax | awk '{print $2}'`
    if [[ "$ssh_interval2" -gt 900 ]];then
        echo "ClientAliveInterval设置为${ssh_interval2},不符合要求，建议设置为300-900之间" >> $str2
    elif [[ "$ssh_interval2" -ge 300 && "$ssh_interval2" -le 900 ]];then
        echo "ClientAliveInterval设置为${ssh_interval2}符合要求" >> $str2
    else
        echo "ClientAliveInterval设置为${ssh_interval2},不符合要求，建议设置为300-900之间" >> $str2
    fi
    
    if [[ "$ssh_countmax2" -gt 3 ]];then
        echo "ClientAliveCountMax设置为${ssh_countmax2},不符合要求，建议设置为0-3之间" >> $str2
    elif [[ "$ssh_countmax2" -ge 0 && "$ssh_countmax2" -le 3 ]];then
        echo "ClientAliveCountMax设置为${ssh_countmax2},符合要求" >> $str2
    else
        echo "ClientAliveCountMax设置为${ssh_countmax2},不符合要求，建议设置为0-3之间" >> $str2
    fi    
else
    echo "请取消ClientAliveInterval和ClientAliveCountMax前面的注释" >> $str2
fi
echo "-----------------------------------" >> $str2

echo "[9]检查ssh LogLevel级别" >> $str2
ssh_log=`cat /etc/ssh/sshd_config | grep -v ^# | grep LogLevel | awk '{print $2}'`
if [ $ssh_log ];then
    ssh_log2=`cat /etc/ssh/sshd_config | grep LogLevel | awk '{print $2}'`
    if [ "$ssh_log2" = "INFO" ];then
        echo "LogLevel级别为${ssh_log2},符合要求" >> $str2
    else
        echo "LogLevel级别为${ssh_log2},不符合要求，建议设置为INFO" >> $str2
    fi
else
    echo "请取消LogLevel前的注释" >> $str2
fi
echo "-----------------------------------"  >> $str2
echo "SSH服务配置检查完毕"

echo "" >> $str2
echo "----------------*********重要文件权限检查**********------------------" >> $str2
echo "[10]检查/etc目录下重要文件权限" >> $str2
Passwd=`ls -l /etc/passwd | awk '{print $1}'`
if [ "${Passwd:1:9}" = "rw-r--r--" ];then
    echo "/etc/passwd的权限为644，符合要求" >> $str2
else
    echo "/etc/passwd的权限为${Passwd:1:9},不符合要求" >> $str2
fi

Shadow=`ls -l /etc/shadow | awk '{print $1}'`
if [ "${Shadow:1:9}" = "---------" ];then
    echo "/etc/shadow的权限为000，符合要求"  >> $str2
else
    echo "/etc/shadow的权限为${Shadow:1:9},不符合要求" >> $str2
fi

Group=`ls -l /etc/group | awk '{print $1}'`
if [ "${Group:1:9}" = "rw-r--r--" ];then
    echo "/etc/group的权限为644,符合要求" >> $str2
else
    echo "/etc/group的权限为${Group:1:9},不符合要求" >> $str2
fi

Hosts_allow=`ls -l /etc/hosts.allow | awk '{print $1}'`
if [ "${Hosts_allow:1:9}" = "rw-r--r--" ];then
    echo "/etc/hosts.allow的权限为644，符合要求" >> $str2
else
    echo "/etc/hosts.allow的权限为${hosts_allow}" >> $str2
fi

Hosts_deny=`ls -l /etc/hosts.deny | awk '{print $1}'`
if [ "${Hosts_deny:1:9}" = "rw-r--r--" ];then
    echo "/etc/hosts.deny的权限为644，符合要求" >> $str2
else
    echo "/etc/hosts.deny的权限为${hosts_allow}" >> $str2
fi
echo "----------------------------------------" >> $str2
echo "重要文件权限检查完毕"

echo ""
echo "-----------------*********日志审计*********-------------------"  >> $str2
echo "[11]检查用户认证服务配置"  >> $str2
Alog=`cat /etc/rsyslog.conf | grep  /var/log/secure | grep -E "authpriv\.\*"`
if [ -e /etc/rsyslog.conf ];then
    echo "用户认证服务日志配置为${Alog}" >> $str2
else
    echo "不存在/etc/rsyslog.conf文件"   >> $str2
fi 

echo "[12]检查其他服务配置" >> $str2
Infolog=`cat /etc/rsyslog.conf |grep  /var/log/messages | grep -E "info"`
Cronlog=`cat /etc/rsyslog.conf |grep  /var/log/cron | grep -E "cron"`
Emerglog=`cat /etc/rsyslog.conf |grep -v ^# | grep -E "emerg"`
Bootlog=`cat /etc/rsyslog.conf | grep  /var/log/boot.log |  grep -E "local7\.\*"`
if [ -e /etc/rsyslog.conf ];then
    echo "info级别或大于info级别日志配置为:${Infolog}" >> $str2
    echo "计划任务cron相关的日志配置为:${Cronlog}" >> $str2
    echo "emerg级别日志配置为:${Emerglog}" >> $str2
    echo "boot日志配置为:${Bootlog}" >> $str2
else
    echo "/etc/rsyslog.conf不存在" >> $str2
fi

echo "[13]检查rsyslog是否开启" >> $str2
systemctl status rsyslog | grep active | awk '{print $3}' > /dev/null
if [ $? -eq 0 ];then
    echo "rsyslog正在运行" >> $str2
else
    echo "rsyslog没有开启" >> $str2
fi
echo "日志审计检查完毕" 
echo "------------------------------------" >> $str2

