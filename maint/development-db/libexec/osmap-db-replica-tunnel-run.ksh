#!/bin/ksh
# Dedicated reconnecting SSH transport. No database command or channel reset.
set -u
set +m
umask 077
[ "$#" -eq 0 ] || exit 64
[ "$(/usr/bin/id -un)" = _osmaprepl ] || exit 1
logdir=/var/log/osmap-db-replica
logfile=${logdir}/tunnel.log
[ -d "$logdir" ] && [ ! -L "$logdir" ] || exit 1
[ "$(/usr/bin/stat -f '%u:%Lp' "$logdir")" = "$(/usr/bin/id -u):700" ] || exit 1
[ ! -L "$logfile" ] || exit 1
: >> "$logfile" || exit 1
[ "$(/usr/bin/stat -f '%u:%Lp:%l' "$logfile")" = "$(/usr/bin/id -u):600:1" ] || exit 1
# Capture SSH stderr from its birth, including failures before a listener exists.
# Raw SSH diagnostics stay in this private log, never an acceptance transcript.
exec >> "$logfile" 2>&1
stopping=0
child_pid=
signal_child() {
 [ -n "$child_pid" ] || return 0
 # Recheck ownership if the child exited around a trap/wait boundary. Never
 # signal a historical PID, another supervisor's SSH, or a numeric group.
 observed_parent=$(/bin/ps -p "$child_pid" -o ppid= 2>/dev/null) || return 0
 observed_parent=${observed_parent##* }
 [ "$observed_parent" = "$$" ] || return 0
 kill -TERM "$child_pid" 2>/dev/null || true
}
stop_transport() {
 stopping=1
 # Repeated supervisor signals must not interrupt the final child wait.
 trap '' HUP INT TERM
 signal_child
}
trap stop_transport HUP INT TERM
print -- "REPLICA_TUNNEL_WRAPPER_STARTED pid=$$"
while [ "$stopping" -eq 0 ]; do
 /usr/bin/ssh -F /dev/null -N -T -a -x \
  -i /var/lib/osmap-db-replica/keys/replication \
  -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityAgent=none \
  -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
  -o StrictHostKeyChecking=yes -o UpdateHostKeys=no \
  -o UserKnownHostsFile=/var/lib/osmap-db-replica/known_hosts \
  -o ControlMaster=no -o ControlPersist=no -o ControlPath=none \
  -o ForwardAgent=no -o ExitOnForwardFailure=yes \
  -o ConnectTimeout=5 -o ConnectionAttempts=1 \
  -o ServerAliveInterval=10 -o ServerAliveCountMax=3 \
  -L 127.0.0.1:13306:127.0.0.1:3306 _osmaprepl@216.128.179.75 &
 child_pid=$!
 print -- "REPLICA_TUNNEL_SSH_BORN pid=$child_pid"
 # A stop between spawn and assignment must still dispose this owned child.
 if [ "$stopping" -ne 0 ]; then signal_child; fi
 wait "$child_pid"
 child_status=$?
 if [ "$stopping" -ne 0 ]; then
  # The first wait may have been interrupted by the stop trap. Reap the same
  # direct child; no reconnect is allowed during this final disposition.
  wait "$child_pid" 2>/dev/null || true
  child_pid=
  print -- "REPLICA_TUNNEL_WRAPPER_STOPPED"
  exit 0
 fi
 child_pid=
 print -- "REPLICA_TUNNEL_SSH_EXIT status=$child_status backoff_seconds=5"
 /bin/sleep 5
done
print -- "REPLICA_TUNNEL_WRAPPER_STOPPED"
