#!/bin/bash

echo Deploying docker containter cs-sigserver
docker run -d --name cs-sigserver --restart=always \
  -p 8080:8080 \
  -e "SIGNSERVICE_DATALOCATION=/opt/signservice" \
  -v /etc/localtime:/etc/localtime:ro \
  -v /opt/docker/signservice:/opt/signservice \
  cs-sigserver

echo Done!
