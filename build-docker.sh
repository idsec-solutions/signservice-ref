#!/bin/bash
mvn clean install && mvn -f docker-signservice/pom.xml dockerfile:build dockerfile:push
