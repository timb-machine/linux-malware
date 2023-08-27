#!/bin/bash
#
# ntpd		This shell script takes care of starting and stopping
#		ntpd (NTPv4 daemon).
#
# chkconfig: - 58 74
# description: ntpd is the NTPv4 daemon. \
# The Network Time Protocol (NTP) is used to synchronize the time of \
# a computer client or server to another server or reference time source, \
# such as a radio or satellite receiver or modem.

### BEGIN INIT INFO
# Provides: ntpd
# Required-Start: $network $local_fs $remote_fs
# Required-Stop: $network $local_fs $remote_fs
# Should-Start: $syslog $named ntpdate
# Should-Stop: $syslog $named
# Short-Description: start and stop ntpd
# Description: ntpd is the NTPv4 daemon. The Network Time Protocol (NTP)
#              is used to synchronize the time of a computer client or
#              server to another server or reference time source, such
#              as a radio or satellite receiver or modem.
### END INIT INFO

# Source function library.
. /etc/init.d/functions

# Source networking configuration.
. /etc/sysconfig/network

prog=ntpd
lockfile=/var/lock/subsys/$prog

start() {
	[ "$EUID" != "0" ] && exit 4
	[ "$NETWORKING" = "no" ] && exit 1
	[ -x /usr/sbin/ntpd ] || exit 5
	[ -f /etc/sysconfig/ntpd ] || exit 6
	. /etc/sysconfig/ntpd

        # Start daemons.
        echo -n $"Starting $prog: "
        daemon $prog $OPTIONS
	RETVAL=$?
        echo
	[ $RETVAL -eq 0 ] && touch $lockfile
	return $RETVAL
}

stop() {
	[ "$EUID" != "0" ] && exit 4
        echo -n $"Shutting down $prog: "
	killproc $prog
	RETVAL=$?
        echo
	[ $RETVAL -eq 0 ] && rm -f $lockfile
	return $RETVAL
}

# See how we were called.
case "$1" in
  start)
	start
	;;
  stop)
	stop
	;;
  status)
	status $prog
	;;
  restart|force-reload)
	stop
	start
	;;
  try-restart|condrestart)
	if status $prog > /dev/null; then
	    stop
	    start
	fi
	;;
  reload)
	exit 3
	;;
  *)
	echo $"Usage: $0 {start|stop|status|restart|try-restart|force-reload}"
	exit 2
esac
