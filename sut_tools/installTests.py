#!/usr/bin/env python

import os, sys
import devicemanagerSUT as devicemanager

if (len(sys.argv) <> 3):
  print "usage: install.py <ip address> <localfilename>"
  sys.exit(1)

print "connecting to: " + sys.argv[1]
dm = devicemanager.DeviceManagerSUT(sys.argv[1])

devRoot  = dm.getDeviceRoot()
source   = sys.argv[2]
filename = os.path.basename(source)
target   = os.path.join(devRoot, filename)

dm.pushFile(source, target)
dm.unpackFile(target)
