#!/bin/bash
export GPG_TTY=$(tty)
mvn -f cs-sigserver-consolidated/pom.xml deploy -P release

