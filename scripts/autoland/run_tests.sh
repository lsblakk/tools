export PYTHONPATH=../../../tools/lib/python

#nosetests --with-coverage --cover-erase --cover-package=. test/test_hgpusher.py 
#nosetests --with-coverage --cover-erase --cover-package=. test/test_autoland_queue.py
#nosetests --with-coverage --cover-erase --cover-package=. test/test_dbhandler.py 
#nosetests --with-coverage --cover-erase --cover-package=. test/test_mq_utils.py
nosetests --with-coverage --cover-erase --cover-package=. test/test_schedulerdbpoller.py
#nosetests --with-coverage --cover-erase --cover-package=. test/test_bz_utils.py