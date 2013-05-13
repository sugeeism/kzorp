#!/bin/sh

set -xe

KZORP=/usr/sbin/kzorp
ZORP=/lib/zorp/zorp

#does not work in intrd
#if [ $USER != "root" ]; then
#  echo "ERROR: You need to be root to run this script"
#  exit 1
#fi

if [ ! -f kzorp.expected ]; then
  echo "ERROR: No file kzorp.expected"
  exit 1
fi

if [ "$(find /var/run/zorp/ -name *.pid)" ]; then
  echo "ERROR: pidfile(s) exist in /var/run/zorp/ directory. Zorp is running?"
  echo "       You should stop Zorp and/or delete pid files from /var/run/zorp"
  echo "       in order to run this test."
  exit 1
fi

$ZORP -F -a plug -p policy.py &
sleep 2
$ZORP -F -a plug2 -p policy.py &
sleep 2
PID=`cat /var/run/zorp/zorp-plug.pid`
PID2=`cat /var/run/zorp/zorp-plug2.pid`
$KZORP -d >/tmp/kzorp.output
if ! diff -q kzorp.expected /tmp/kzorp.output > /dev/null 2>&1; then
  EXIT_VALUE=1
  echo "ERROR: kzorp output was not as expected."
  echo
  echo "---[ BEGIN: diff -u kzorp.expected kzorp.output ] ---"
  diff -u kzorp.expected /tmp/kzorp.output || true
  echo "---[ END: diff -u kzorp.expected kzorp.output ] ---"
else
  echo "SUCCESS: kzorp output is as expected."
  EXIT_VALUE=0
fi

rm /tmp/kzorp.output
kill -15 $PID
kill -15 $PID2

exit $EXIT_VALUE

