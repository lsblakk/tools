#!/bin/bash

ROOT=$HOME/autoland-env/tools/scripts/autoland
ACTIVATE=$HOME/autoland-env/bin/activate

HGP_INSTANCES=2         # The default number of hgpushers to launch

function usage {
    echo "usage: $0 [--hgp-instances=N] [--kill-hgp] [--kill-queue]"
    echo -e "  With no arguments, launches a default of $HGP_INSTANCES instances of hgpusher and 1 instance of"
    echo -e "  autoland_queue. Each instance is run in an appropriately named screen session."
    echo -e "Optional Parameters:"
    echo -e "\t--hgp-instances=N: number of hgpusher instances to start"
    echo -e "\t--kill-hgp: kill all hgpusher instances"
    echo -e "\t--kill-queue: kill the autoland-queue instance"
    echo -e "\t--help | -h: display this help message"
}

for i in $@; do
  case $i in
  --hgp-instances=*)
      HGP_INSTANCES=${i#*=}
      ;;
  --kill-hgp)
      KILL_HGP=1
      ;;
  --kill-queue)
      KILL_QUEUE=1
      ;;
  --help|-h)
      usage
      exit 0
      ;;
  *)
      echo -e "Invalid argument $1"
      usage
      exit 1
      ;;
  esac
done

if [ $KILL_QUEUE ]; then
    echo -n -e "Killing autoland_queue..."
    screen -ls | grep 'queue' > /dev/null
    if [ $? -eq 0 ]; then
        screen -X -S queue quit > /dev/null
        echo -e "\t\t[DONE]"
    else
        echo -e "\t\t[FAIL]"
        echo -e "\tautoland_queue not running."
    fi
fi
if [ $KILL_HGP ]; then
    instances=`screen -ls | grep hgpusher | awk '{split($1,a,"."); print a[1]}'`
    if [[ $instances && ${#instances[@]} -ne 0 ]]; then
        for hgp in $instances; do
            echo -n "Killing $hgp.hgpusher..."
            screen -X -S $hgp quit > /dev/null
            echo -e "\t\t[DONE]"
        done
    else
        echo -e "Killing hgpusher...\t\t\t[FAIL]"
        echo -e "\tno hgpushers running"
    fi
fi

if [[ $KILL_HGP || $KILL_QUEUE ]]; then
    exit
fi

echo "Activate autoland-env"
source $ACTIVATE

echo "cd $ROOT"
cd $ROOT

echo -n -e "\nLaunching autoland_queue..."
screen -ls | grep 'queue' > /dev/null
if [ $? -ne 0 ]; then
    screen -S 'queue' -d -m python $ROOT/autoland_queue.py
    echo -e "\t\t[DONE]"
else
    echo -e "\t\t[FAIL]"
    echo -e "\tQueue already running."
fi

for i in `seq 1 $HGP_INSTANCES`; do
    SNAME=hgpusher-$i
    echo -n "Launching $SNAME..."
    screen -ls | grep $SNAME > /dev/null
    if [ $? -ne 0 ] ; then
        screen -S $SNAME -d -m python $ROOT/hgpusher.py
        echo -e "\t\t\t[DONE]"
    else
        echo -e "\t\t\t[FAIL]"
        echo -e "\t$SNAME already running."
    fi
done

HGP_COUNT=`screen -ls | grep hgpusher | wc -l`
echo -e "\nThere are a total of $HGP_COUNT hgpushers running"

