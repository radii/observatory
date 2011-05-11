#!/bin/bash

# A Cripled version of rebuild.sh, with no acerts

# run this to build a comprehensive and consistent version of everything after
# transvalidity has been computed; 
# note this script requires a callable scripted named "ssldb" to be in the path 
# which launches the DB, logs the user in and uses the schema for the observatory

set -x

# CHANGE ME
export RESULTS_ROOT=/home/jesse/dec_2010/scan/

cd $RESULTS_ROOT
TARGETS=`echo *.x.x.x`
echo Raw data dirs are: $TARGETS
cd ~-
TABLES=""
for n in $TARGETS ; do
  TNAME=certs`echo $n | sed s/\.x\.x\.x//`
  echo $TNAME
  TABLES="$TABLES $TNAME"
done
echo Tables are defined as $TABLES
 
# Make the "seen" table, containing all the chains and the IPs they were at
./stitch_tables.py --seen seen $TABLES

# Extract the names (both Subject Common Names and x509v3 Subject Alternative
# Names) that certs pertain to.  This one does the names in valid certs:
./namestractor.py

# Type convert Valid:Not Before|After into "startdate" and "endate" (proper
# mysql datetime columns)
cat timestamps.sql | obsdb

# Build a table of all the root certs
./hackparse.py --roots --table roots --create 

# This queryset happens to build the useful ca_skids table.
obsdb < questions/make-duplicate-names.sql
obsdb < questions/rare_and_interesting_cas.sql
