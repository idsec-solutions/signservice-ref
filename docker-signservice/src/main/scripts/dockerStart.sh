#!/usr/bin/env bash

TOMCAT_HOME=/opt/tomcat

#
# This is the docker run script that is placed in the $CATALINA_HOME/bin folder to be executed inside a docker container
#

: ${SIGNSERVICE_DATALOCATION:=/opt/signservice}
: ${DEBUG_MODE:=false}

export SIGNSERVICE_DATALOCATION=$SIGNSERVICE_DATALOCATION
export DEBUG_MODE=$DEBUG_MODE

#
# LOG Levels  WARN, INFO, FINE
#
: ${LOGLEVEL_SIGSERVER:=INFO}
: ${$MAXLOGDAYS:=7}

#
# TLS Settings
#
: ${TOMCAT_TLS_SERVER_KEY:=$SIGNSERVICE_DATALOCATION/tomcat/tomcat-key.pem}
: ${TOMCAT_TLS_SERVER_CERTIFICATE:=$SIGNSERVICE_DATALOCATION/tomcat/tomcat-cert.pem}
: ${TOMCAT_TLS_SERVER_CERTIFICATE_CHAIN:=$SIGNSERVICE_DATALOCATION/tomcat/tomcat-chain.pem}
: ${TOMCAT_TLS_SERVER_KEY_TYPE:=RSA}

#
# System settings
#
: ${JVM_MAX_HEAP:=1536m}
: ${JVM_START_HEAP:=512m}
: ${DEBUG_PORT:=8000}

export JAVA_OPTS="-XX:MaxPermSize=512m"
export CATALINA_OPTS="\
          -Xmx${JVM_MAX_HEAP}\
          -Xms${JVM_START_HEAP}\
          -Dtomcat.tls.server-key=$TOMCAT_TLS_SERVER_KEY \
          -Dtomcat.tls.server-key-type=$TOMCAT_TLS_SERVER_KEY_TYPE \
          -Dtomcat.tls.server-certificate=$TOMCAT_TLS_SERVER_CERTIFICATE \
          -Dtomcat.tls.certificate-chain=$TOMCAT_TLS_SERVER_CERTIFICATE_CHAIN \
          -Dtomcat.loglevel.sigserv=$LOGLEVEL_SIGSERVER \
          -Dtomcat.maxlogdays=$MAXLOGDAYS \
          -Dorg.apache.xml.security.ignoreLineBreaks=true \
"

#
# Debug
#
export JPDA_ADDRESS=${DEBUG_PORT}
export JPDA_TRANSPORT=dt_socket

if [ $DEBUG_MODE == true ]; then
    echo "Running in debug"
    ${TOMCAT_HOME}/bin/catalina.sh jpda run
else
    echo "Running in normal mode"
    ${TOMCAT_HOME}/bin/catalina.sh run
fi
