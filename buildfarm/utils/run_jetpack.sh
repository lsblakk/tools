#!/bin/bash
# Usage: %prog platform [tarball_url] [ftp_url] [extension]

# Script to pull down the latest jetpack sdk tarball, unpack it, and run its tests against the 
# executable of whatever valid platform is passed.

set -e
JETPACK_TARBALL="jetpack.tar.bz2"
POLLER_DIR="jetpack-poller"
JETPACK_DIR="jetpack"

if [ $# = 1 ]; then
  # we're running this as an m-c change triggered test suite
  if [ ! -d "./jetpack" ]; then
    echo "No jetpack directory present!  Cannot run test suite."
    exit 1
  else
    # Set up for running jetpack test suite
    BASE_PATH=$(pwd)
    cd $JETPACK_DIR
    wget -i "jetpack-location.txt" -O $JETPACK_TARBALL
  fi
elif [ $# = 4 ]; then
  # this is a jetpack poller triggered test run
  if [ -e "$POLLER_DIR" ]; then
    rm -rf $POLLER_DIR
  fi
  mkdir $POLLER_DIR && cd $POLLER_DIR
  # grab the tip of addon-sdk
  wget -O $JETPACK_TARBALL $2
  # get the platform's nightly from the ftp dir
  wget -r -l1 -nd -np -A$4 "ftp://"$3
  BASE_PATH=$(pwd)
else
  echo "Incorrect number of arguments, should have either 1 (platform) or 4 (platform, tarball_url, ftp_url, extension)."
  exit 1
fi  
 # handling for each platform's executable path
if [ "$1" == 'linux' -o "$1" == 'linux64' -o "$1" == 'fedora' -o "$1" == 'fedora64' ]; then
  APP_PATH=$BASE_PATH/firefox/firefox
  POLLER_CMD='tar -xjvf *'$4
elif [ "$1" == 'macosx' -o "$1" == 'macosx64' -o "$1" == 'leopard' -o "$1" == 'snowleopard' -o "$1" == 'lion' -o "$1" == 'snowleopard-r4' ]; then
  POLLER_CMD='../scripts/buildfarm/utils/installdmg.sh *'$4
elif [ "$1" == 'win32' -o "$1" == 'win7' -o "$1" == 'win764' -o "$1" == 'w764' -o "$1" == 'xp' ]; then
  APP_PATH=$BASE_PATH/firefox/firefox.exe
  # The --exclude=*.app is here to avoid extracting a
  # symlink on win32 that is only relevant to OS X.
  # It would be nice if we could just tell tar to
  # ignore symlinks...
  UNTAR_ARGS=--exclude=*.app
  POLLER_CMD='unzip -o *'$4
else
  echo "$1 is not a valid platform."
  exit 1
fi

if [ $# = 4 ]; then
  # jetpack poller runs need to
  # prepare (unzip, install, untar) the executable
  if [ "$POLLER_CMD" ]; then
    $POLLER_CMD
  fi
fi

# Make sure we have an app to run the test suite against
# Mac builds require getting the $APP_PATH after installing the dmg (for jetpack-poller)
if [ "$1" == 'macosx' -o "$1" == 'macosx64' -o "$1" == 'leopard' -o "$1" == 'snowleopard' -o "$1" == 'lion' -o "$1" == 'snowleopard-r4' ]; then
  APP_PATH=$(find $BASE_PATH -maxdepth 1 -type d -name '*.app')
fi
if [ ! -e "$APP_PATH" ]; then
  echo "The location \"$APP_PATH\" does not exist"
  exit 1
fi

# Run it!
tar -xvf $JETPACK_TARBALL $UNTAR_ARGS
# Find the sdk dir to run tests in
SDK_DIR=$(ls . | grep 'addon-sdk*')
if [ -d $SDK_DIR ]; then
  cd $SDK_DIR
  python bin/cfx --verbose testall -a firefox -b $APP_PATH
else
  echo "SDK_DIR is either missing or invalid."
  exit 1
fi
