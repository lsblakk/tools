#!/bin/bash
set -e
SCRIPTS_DIR="$(readlink -f $(dirname $0)/../..)"

if [ -z "$REVISION" ]; then
    export REVISION="default"
fi

if [ -z "$HG_REPO" ]; then
    export HG_REPO="http://hg.mozilla.org/mozilla-central"
fi

if [ -f "$PROPERTIES_FILE" ]; then
    PYTHON="/tools/python/bin/python"
    JSONTOOL="$PYTHON $SCRIPTS_DIR/buildfarm/utils/jsontool.py"

    builder=$($JSONTOOL -k properties.buildername $PROPERTIES_FILE)
    slavename=$($JSONTOOL -k properties.slavename $PROPERTIES_FILE)
    master=$($JSONTOOL -k properties.master $PROPERTIES_FILE)

    builddir=$(basename $(readlink -f .))
    branch=$(basename $HG_REPO)

    # Clobbering
    if [ -z "$CLOBBERER_URL" ]; then
        export CLOBBERER_URL="http://build.mozilla.org/clobberer"
    fi

    cd $SCRIPTS_DIR/../..
    python $SCRIPTS_DIR/clobberer/clobberer.py -s scripts -s $PROPERTIES_FILE \
        $CLOBBERER_URL $branch "$builder" $builddir $slavename $master

    # Purging
    cd $SCRIPTS_DIR/..
    python $SCRIPTS_DIR/buildfarm/maintenance/purge_builds.py \
        -s 4 -n info -n 'rel-*' -n $builddir
fi

python $SCRIPTS_DIR/buildfarm/utils/hgtool.py --rev $REVISION --tbox $HG_REPO src || exit 2

# Put our short revisions into the properties directory for consumption by buildbot.
if [ ! -d properties ]; then
    mkdir properties
fi
pushd src; GOT_REVISION=`hg parent --template={node} | cut -c1-12`; popd
echo "revision: $GOT_REVISION" > properties/revision
echo "got_revision: $GOT_REVISION" > properties/got_revision

if [ ! -d objdir ]; then
    mkdir objdir
fi
cd objdir

# Setup a basic mozconfig file
echo '. $topsrcdir/browser/config/mozconfig' > mozconfig
echo 'ac_add_options --enable-valgrind' >> mozconfig
echo 'ac_add_options --with-ccache' >> mozconfig
echo 'ac_add_options --disable-jemalloc' >> mozconfig
echo 'ac_add_options --disable-elf-hack' >> mozconfig
echo 'ac_add_options --enable-optimize="-g -O -freorder-blocks"' >> mozconfig
echo 'CC=/tools/gcc-4.3.3/installed/bin/gcc' >> mozconfig
echo 'CXX=/tools/gcc-4.3.3/installed/bin/g++' >> mozconfig

export G_SLICE=always-malloc

if [ "`uname -m`" = "x86_64" ]; then
    export LD_LIBRARY_PATH=/tools/gcc-4.3.3/installed/lib64
else
    export LD_LIBRARY_PATH=/tools/gcc-4.3.3/installed/lib
fi

make -f ../src/client.mk MOZCONFIG=$PWD/mozconfig configure || exit 2
make -j4 || exit 2
make package || exit 2

debugger_args="--error-exitcode=1 --smc-check=all --gen-suppressions=all --leak-check=full --num-callers=50"
suppression_file=$PWD/_valgrind/${MACHTYPE}.sup
if [ -f $suppression_file ]; then
    debugger_args="$debugger_args --suppressions=$suppression_file"
fi

export OBJDIR=.
export JARLOG_DIR=./jarlog/en-US
python _profile/pgo/profileserver.py --debugger=valgrind --debugger-args="$debugger_args" || exit 1
