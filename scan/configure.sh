#!/bin/bash

# make sure we have all the tools lying around
  SEDBIN=`which sed  `; if [   "${SEDBIN}" == "" ]; then \
		>&2 echo "FATAL. $0 FAILED. Missing sed.";   exit -1; fi
 CURLBIN=`which curl `; if [  "${CURLBIN}" == "" ]; then \
		>&2 echo "FATAL. $0 FAILED. Missing curl.";  exit -1; fi
XARGSBIN=`which xargs`; if [ "${XARGSBIN}" == "" ]; then \
		>&2 echo "FATAL. $0 FAILED. Missing xargs."; exit -1; fi
  DIGBIN=`which dig  `; if [   "${DIGBIN}" == "" ]; then \
		>&2 echo "FATAL. $0 FAILED. Missing dig.";   exit -1; fi

# update the hostname variable in the Makefile with the actual name of this
# host (so that reverse lookups match, ideally there's an MX record too but
# that's may be asking too much)
sed s/"^hostname = .*\$"/"hostname = \"\\\\\"`curl -s http://curlmyip.com \
	| xargs dig +short -x | sed s/"\.\$"//g`\\\\\"\""/g _Makefile > Makefile
