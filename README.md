# automatic-slr
A simple script to automatically generate Security Lifecycle Reviews (SLR) 

This script requires Python 3 and the [Requests](http://docs.python-requests.org/en/master/) and [Logzero](https://logzero.readthedocs.io/en/latest/) libraries to be installed to function correctly.

Two command line arguments are required with an optional argument:

```
-c / --config  - Path to the configuration .ini file (required)
-l / --log     - Path to the .log file (required)
-v / --verbose - Enable verbose logging output to the console, log file and Syslog (optional)
```

Help is also accessible by running the script with -h or --help.

```
$ python3 automatic-slr.py --help
usage: automatic-slr.py [-h] -c CONFIG -l LOG [-v]

Palo Alto Networks Automated SLR Generator (Version: 1.0.0)

optional arguments:
  -h, --help                 show this help message and exit
  -c CONFIG, --config CONFIG Define the configuration file
  -l LOG, --log LOG          Define the log file
  -v, --verbose              Enable verbose logging output to the console and log file
```

Example without verbose logging:
```
$ python3 automatic-slr.py --config default-configuration.ini --log /var/log/automatic-slr/default.log
```

Example with verbose logging:
```
$ python3 automatic-slr.py --config default-configuration.ini --log /var/log/automatic-slr/default.log --verbose
```

For full documentation consult the wiki here: https://github.com/Mediab0t/automatic-slr/wiki
