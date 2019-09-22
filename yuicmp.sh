#!/bin/sh
#
# Script for kicking YUI Compressor (JavaScript compressor)
#
# yuicmp -h
# yuicmp -o test-min.js test.js
# yuicmp -o test-min.css test.css
export YUI_HOME="/Users/zhoujh/Develop/yuicompressor"
CP="."
CP="${CP};${YUI_HOME}/jargs-1.0.jar"
CP="${CP};${YUI_HOME}/rhino-1.7R2.jar"
export CLASSPATH=${CP}
JAR="${YUI_HOME}/yuicompressor-2.4.8.jar"
java -jar ${JAR} $1 $2 $3 $4 $5 $6 $7 $8 $9