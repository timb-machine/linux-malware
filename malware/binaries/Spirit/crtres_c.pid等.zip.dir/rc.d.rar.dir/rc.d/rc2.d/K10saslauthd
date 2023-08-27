#! /bin/bash
#
# saslauthd      Start/Stop the SASL authentication daemon
#
# chkconfig: - 65 10
# description: Saslauthd is a server process which handles plaintext \
#              authentication requests on behalf of the cyrus-sasl library.
# processname: saslauthd

### BEGIN INIT INFO
# Provides: saslauthd
# Required-Start: $local_fs $network
# Required-Stop: $local_fs $network
# Short-Description: Start/Stop the SASL authentication daemon
# Description: Saslauthd is a server process which handles plaintext
#              authentication requests on behalf of the cyrus-sasl library.
### END INIT INFO

# Source function library.
. /etc/init.d/functions

# Source our configuration file for these variables.
SOCKETDIR=/var/run/saslauthd
MECH=shadow
FLAGS=
if [ -f /etc/sysconfig/saslauthd ] ; then
	. /etc/sysconfig/saslauthd
fi

RETVAL=0

# Set up some common variables before we launch into what might be
# considered boilerplate by now.
prog=saslauthd
path=/usr/sbin/saslauthd
lockfile=/var/lock/subsys/$prog
pidfile=/var/run/saslauthd/saslauthd.pid

start() {
	[ -x $path ] || exit 5
	echo -n $"Starting $prog: "
	daemon $DAEMONOPTS $path -m $SOCKETDIR -a $MECH $FLAGS
	RETVAL=$?
	echo
	[ $RETVAL -eq 0 ] && touch $lockfile
	return $RETVAL
}

stop() {
	echo -n $"Stopping $prog: "
	killproc $prog
	RETVAL=$?
	echo
	[ $RETVAL -eq 0 ] && rm -f $lockfile
	return $RETVAL
}	

restart() {
  	stop
	start
}	

reload() {
	restart
}

force_reload() {
	restart
}

rh_status() {
	# run checks to determine if the service is running or use generic status
	status -p $pidfile $prog
}

rh_status_q() {
	rh_status >/dev/null 2>&1
}            

case "$1" in
  start)
	rh_status_q && exit 0
  	start
	;;
  stop)
	rh_status_q || exit 0
  	stop
	;;
  restart)
  	restart
	;;
  reload)
	rh_status_q || exit 7
	reload
	;;
  force-reload)
	force_reload
	;;
  status)
	rh_status
	;;
  condrestart|try-restart)
	rh_status_q || exit 0
	restart
	;;
  *)
	echo $"Usage: $0 {start|stop|status|restart|condrestart|try-restart|reload|force-reload}"
	exit 2
esac

exit $?
