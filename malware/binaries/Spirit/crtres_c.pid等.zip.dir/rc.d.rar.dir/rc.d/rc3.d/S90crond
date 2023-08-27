#!/bin/sh
#
# crond          Start/Stop the cron clock daemon.
#
# chkconfig: 2345 90 60
# description: cron is a standard UNIX program that runs user-specified \
#              programs at periodic scheduled times. vixie cron adds a \
#              number of features to the basic UNIX cron, including better \
#              security and more powerful configuration options.

### BEGIN INIT INFO
# Provides: crond crontab
# Required-Start: $local_fs $syslog
# Required-Stop: $local_fs $syslog
# Default-Start:  2345
# Default-Stop: 90
# Short-Description: run cron daemon
# Description: cron is a standard UNIX program that runs user-specified 
#              programs at periodic scheduled times. vixie cron adds a 
#              number of features to the basic UNIX cron, including better 
#              security and more powerful configuration options.
### END INIT INFO

[ -f /etc/sysconfig/crond ] || { 
    [ "$1" = "status" ] && exit 4 || exit 6 
}

RETVAL=0
prog="crond"
exec=/usr/sbin/crond
lockfile=/var/lock/subsys/crond
config=/etc/sysconfig/crond

# Source function library.
. /etc/rc.d/init.d/functions

[ $UID -eq 0 ] && [ -e /etc/sysconfig/$prog ] && . /etc/sysconfig/$prog

start() {
    if [ $UID -ne 0 ] ; then
        echo "User has insufficient privilege."
        exit 4
    fi
    [ -x $exec ] || exit 5
    [ -f $config ] || exit 6
    echo -n $"Starting $prog: "
    daemon $prog $CRONDARGS
    retval=$?
    echo
    [ $retval -eq 0 ] && touch $lockfile
}

stop() {
    if [ $UID -ne 0 ] ; then
        echo "User has insufficient privilege."
        exit 4
    fi
    echo -n $"Stopping $prog: "
	if [ -n "`pidfileofproc $exec`" ]; then
		killproc $exec
		RETVAL=3
	else
		failure $"Stopping $prog"
	fi
    retval=$?
    echo
    [ $retval -eq 0 ] && rm -f $lockfile
}

restart() {
    rh_status_q && stop
    start
}

reload() {
	echo -n $"Reloading $prog: "
	if [ -n "`pidfileofproc $exec`" ]; then
		killproc $exec -HUP
	else
		failure $"Reloading $prog"
	fi
	retval=$?
	echo
}

force_reload() {
	# new configuration takes effect after restart
    restart
}

rh_status() {
    # run checks to determine if the service is running or use generic status
    status -p /var/run/crond.pid $prog
}

rh_status_q() {
    rh_status >/dev/null 2>&1
}


case "$1" in
    start)
        rh_status_q && exit 0
        $1
        ;;
    stop)
        rh_status_q || exit 0
        $1
        ;;
    restart)
        $1
        ;;
    reload)
        rh_status_q || exit 7
        $1
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

