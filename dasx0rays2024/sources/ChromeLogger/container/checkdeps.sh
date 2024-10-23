#!/bin/bash

get_build_id() {
    readelf -n $1 | grep "Build ID" | awk '{print $3}'
}

cd lib
for soname in lib*so*; do
    srcID=$(get_build_id $soname)
    if [ -L /lib/x86_64-linux-gnu/$soname ]; then
        realso=/lib/x86_64-linux-gnu/$(readlink /lib/x86_64-linux-gnu/$soname)
    else
        realso=/lib/x86_64-linux-gnu/$soname
    fi
    dstID=$(get_build_id $realso)
    if [ "$srcID" != "$dstID" ]; then
        mv $soname $realso
    fi
done
cd ..
unset -f get_build_id
