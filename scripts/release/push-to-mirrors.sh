#!/bin/sh
set -e
set -x
# This ugly hack is a cross-platform (Linux/Mac/Windows+MSYS) way to get the
# absolute path to the directory containing this script
pushd `dirname $0` &>/dev/null
MY_DIR=$(pwd)
popd &>/dev/null
SCRIPTS_DIR="$MY_DIR/../../"
PYTHON="/tools/python/bin/python"
if [ ! -x $PYTHON ]; then
    PYTHON=python
fi
JSONTOOL="$PYTHON $SCRIPTS_DIR/buildfarm/utils/jsontool.py"
workdir=`pwd`

branchConfig=$1
action=$2 # check or push

branch=$(basename $($JSONTOOL -k properties.branch $PROPERTIES_FILE))
builder=$($JSONTOOL -k properties.buildername $PROPERTIES_FILE)
builddir=$($JSONTOOL -k properties.builddir $PROPERTIES_FILE)
slavename=$($JSONTOOL -k properties.slavename $PROPERTIES_FILE)
master=$($JSONTOOL -k properties.master $PROPERTIES_FILE)
releaseConfig=$($JSONTOOL -k properties.release_config $PROPERTIES_FILE)
releaseTag=$($JSONTOOL -k sourcestamp.revision $PROPERTIES_FILE)

if [ -z "$BUILDBOT_CONFIGS" ]; then
    export BUILDBOT_CONFIGS="http://hg.mozilla.org/build/buildbot-configs"
fi
if [ -z "$CLOBBERER_URL" ]; then
    export CLOBBERER_URL="http://build.mozilla.org/clobberer"
fi

cd $SCRIPTS_DIR/../../..
$PYTHON $SCRIPTS_DIR/clobberer/clobberer.py -s build $CLOBBERER_URL $branch \
  $builder $builddir $slavename $master
cd $SCRIPTS_DIR/../..
$PYTHON $SCRIPTS_DIR/buildfarm/maintenance/purge_builds.py \
  -s 0.3 -n info -n 'release-*' -n $builddir
cd $workdir

$PYTHON $MY_DIR/push-to-mirrors.py -c $branchConfig -r $releaseConfig \
  -b $BUILDBOT_CONFIGS -t $releaseTag $action