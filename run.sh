#!/bin/sh
java -cp target/manager-0.0.1-SNAPSHOT.jar com.sam.key.manager.Generator
trap 'sleep infinity' EXIT