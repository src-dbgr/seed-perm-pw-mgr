#!/bin/sh
cd target
java -cp manager-0.0.1-SNAPSHOT.jar com.sam.key.manager.Generator
trap 'sleep infinity' EXIT