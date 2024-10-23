#!/bin/bash
if [[ "z${DASFLAG}z" == "zz" ]]; then
    DASFLAG="DASCTF{test_flag}"
fi
echo $DASFLAG > flag
echo $DASFLAG > /flag
chmod 644 flag /flag
unset DASFLAG

echo "Failed xinetd" > /etc/banner_fail

/etc/init.d/xinetd start
sleep infinity
