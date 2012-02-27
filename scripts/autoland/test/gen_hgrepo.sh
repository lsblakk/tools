#!/bin/bash
if [ $# -eq 1 ]; then
    if [ $1 == '--clean' ]; then
        rm -rf repo
        rm -rf try
        exit 0
    fi
    exit 1
fi

if [ -d 'repo' ]; then
    rm -rf repo
fi
mkdir repo
cd repo
pwd
hg init

username="HG Pusher <hg.pusher@mozilla.com>"

echo "Hello world $RANDOM" > hello.txt
hg add hello.txt
hg commit -m "Adding hello"

echo "Generate a patch" >> hello.txt
hg commit -m "bug 1: Creating patch" -u "$username"
hg export -g -r tip > hello_patch.patch
hg backout -m "Backout to allow reapply" -u "$username" tip

echo "This patch shouldn't apply" >> hello.txt
hg commit -m "bug 2: Creating patch 2" -u "$username"
hg diff -U8 -r tip > hello_patch.diff
hg backout -m "Backout 2nd patch" -u "$username" tip
hg add hello_patch.patch
hg add hello_patch.diff
hg commit -m "adding patch files" -u "$username"

cd -
# Set up our try "server"
hg clone repo try
