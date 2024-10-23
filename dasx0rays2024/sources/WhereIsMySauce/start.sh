#!/bin/bash
if [[ "z${DASFLAG}z" == "zz" ]]; then
    DASFLAG="DASCTF{test_flag}"
fi
sed -i "s/FLAG/$DASFLAG/g" /usr/src/sauce/liquid.c
unset DASFLAG
debuginfod -F service
