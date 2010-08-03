#!/usr/bin/python

import hashlib
import os
from optparse import OptionParser

from flasher_wrapper import flash_n900

def hash_file(filename, chunk_size=2**10, algorithm='sha1'):
    if not filename:
        return None
    if not os.path.exists(filename):
        return None
    f = open(filename)
    if algorithm.__class__ is str:
        hash_obj = hashlib.new(algorithm)
    else:
        hash_obj = algorithm
    while True:
        data = f.read(chunk_size)
        if not data:
            break
        hash_obj.update(data)
    return hash_obj.hexdigest()

def validate_file(filename, good_hash, algorithm='sha1'):
    current_hash=hash_file(filename, algorithm=algorithm)
    if current_hash != good_hash:
        return False
    else:
        return True

if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option('-d', '--debug', help='Be noisy', action='store_true',
                        dest='debug', default=False)
    options, args = parser.parse_args()

    main_file = 'RX-51_2009SE_10.2010.19-1.002_PR_COMBINED_002_ARM.bin'
    main_hash = 'a4a22b3c92407c293ab197a8acb7480058d52a20'
    emmc_file = 'RX-51_2009SE_10.2010.13-2.VANILLA_PR_EMMC_MR0_ARM.bin'
    emmc_hash = 'a90cd06ef46e3a02d4feb33d4ec0ca190ab0ead4'
    root_file = 'moz-n900-v1.6.ubi'
    root_hash = '14e72cf94f5105e63c405267c68a0d2e5a4814c2'
    if not validate_file(main_file, main_hash):
        print 'Invalid main file'
        exit(1)
    if not validate_file(emmc_file, emmc_hash):
        print 'Invalid emmc file'
        exit(1)
    if not validate_file(root_file, root_hash):
        print 'Invalid root file'
        exit(1)


    flash_n900(
        main=main_file,
        emmc=emmc_file,
        rootfs=root_file,
        debug=options.debug,
    )
