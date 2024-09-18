#!/bin/bash
#
# Author: Sir Ocram aka 0xFF00FF
# Date: 09/18/2024

TARGET="$1"
DIR="$PWD/domains"

if [ -z $TARGET ]; then
	echo -e "Usage: crt.sh <keyword>"
	echo -e "<keyword> should be clients name"
	exit
fi

echo -e "[+] Making directory $DIR"
mkdir $DIR
echo -e "[+] Downloading from https://crt.sh"
TARGET=${TARGET// /+}
echo -e "[+] url: https://crt.sh/?q=$TARGET"
curl -s https://crt.sh/?q=$TARGET > $DIR/curl.txt
echo -e "[+] Saving urls to $DIR/urls.txt"
cat $DIR/curl.txt | grep jura.ch | grep -oP '(?<=<TD>).*?(?=</TD>)' | sed 's/<BR>/\n/g' | sort | uniq > $DIR/domains.txt

echo "[+] Checking if url is live"
TOTAL=`wc -l < $DIR/domains.txt`
count=1
for url in $(cat $DIR/domains.txt); do
  echo "Checking domain $count/$TOTAL: $url"
  status=$(curl --max-time 10 -o /dev/null -s -w "%{http_code}\n" $url)
  if [ "$status" -ne 000 ] && [ "$status" -ne 404 ]; then
    if [ "$status" -eq 301 ]; then
      https_url="${url/http:/https:}"
      echo "Retrying with HTTPS: $https_url"
      status=$(curl -L --max-time 10 -o /dev/null -s -w "%{http_code}\n" $https_url)
      if [ "$status" -eq 200 ]; then
        echo "https://$https_url" >> $DIR/live_domains.txt
      else
      	echo "($status) $url"
      fi
    else
      echo "http://$url" >> $DIR/live_domains.txt
    fi
  else
    echo "($status) $url"
  fi
  count=$((count + 1))
done

TOTALLive=`wc -l < $DIR/live_domains.txt`
echo -e "[+] Total Number of live domains: $TOTALLive"

echo -e "[+] Sending live domains through Burp Suite"
for url in $(cat $DIR/live_domains.txt); do
  echo "Sending $url to Burp"
  status=$(curl -L --max-time 10 -o /dev/null -s -w "%{http_code}\n" -x http://127.0.0.1:8080 $url)
done

echo -e "[+] Cleaning"
rm $DIR/curl.txt
rm $DIR/domains.txt
