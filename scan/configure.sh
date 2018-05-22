#!/bin/bash

# Make sure we have all the tools available.
 CURLBIN=`which curl `; if [  "${CURLBIN}" == "" ]; then \
		>&2 echo "FATAL. $0 FAILED. Missing curl.";  exit -1; fi
  DIGBIN=`which dig  `; if [   "${DIGBIN}" == "" ]; then \
		>&2 echo "FATAL. $0 FAILED. Missing dig.";   exit -1; fi
  AWKBIN=`which awk  `; if [   "${AWKBIN}" == "" ]; then \
		>&2 echo "FATAL. $0 FAILED. Missing awk.";   exit -1; fi
  SEDBIN=`which sed  `; if [   "${SEDBIN}" == "" ]; then \
		>&2 echo "FATAL. $0 FAILED. Missing sed.";   exit -1; fi

# Update the hostname variable in the Makefile with the FQDN of this host.
myipaddr=$(curl -s --max-time 5 https://tools.100tx.org/myipaddress/)
if [ "$myipaddr" == "" ]; then
	myipaddr="127.0.0.1"
fi

myfqdn=$(dig +short -x $myipaddr 2> /dev/null)
if [ "$myfqdn" == "" ]; then
	myfqdn=$(echo "$myipaddr" | awk -F \. \
		'{
			for (i = NF; i > 1; i--) {
				printf("%s.", $i);
			}
			printf("%s.in-addr.arpa.\n", $1);
		}'
	)
fi

sed s/"^hostname = .*\$"/"hostname = \"\\\\\"$myfqdn\\\\\"\""/g \
	_Makefile > Makefile
