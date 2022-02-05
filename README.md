# UAC_processor

This is a work in progress top process the output from Thiago Lahr's UAC collection script (https://github.com/tclahr/uac).

Do to the usage of CIRCL hash lookup' api pyhashlookup, this will not run on Windows.  

This script has only been tested on Ubuntu 20.04.3 LTS using Python 3.8.10 against a UAC v2 collection against an Ubuntu OS.  Very limited testing has been done.  

All output is in a sql database for each collected tar.gz file (not tested).


Requirements:
* python3
* pip install pandas
* pip install pyhashlookup
* pip install yara-python
