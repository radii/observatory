#!/bin/bash

# run this to build a comprehensive and consistent version of everything after
# transvalidity has been computed; 
# note this script requires a callable scripted named "ssldb" to be in the path 
# which launches the DB, logs the user in and uses the schema for the observatory

set -x

# CHANGE ME
export RESULTS_ROOT=/home/pde/rescan-results/

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
 
# export TABLES=`echo certs{0,0b,1,1b,2,3,4,4b,5,6,7,8,9,9b,10,10bcd,11,11b,134}`

# This version of all_certs (all certs) includes transvalidity and has a 
# canonical certid for each cert
./stitch_tables.py --allcerts --into all_certs $TABLES

# --empty: define the schema for valid_certs but don't actually put anything into it
./stitch_tables.py --into valid_certs --empty $TABLES

# Copy valid all_certs into valid_certs, to keep the ids consistent
./acerts_to_vcerts.py

# Make the "seen" table, containing all the chains and the IPs they were at
./stitch_tables.py --seen seen $TABLES

# Extract the names (both Subject Common Names and x509v3 Subject Alternative
# Names) that certs pertain to.  This one does the names in valid certs:
./namestractor.py

# These are for the names in all certs:
./namestractor.py --from all_certs --into anames --san_into aSANToCert --scn_into aSCNToCert

# Type convert Valid:Not Before|After into "startdate" and "endate" (proper
# mysql datetime columns)
cat timestamps.sql | obsdb

# Build a table of all the root certs
./hackparse.py --roots --table roots --create 

# This queryset happens to build the useful ca_skids table.
obsdb < questions/make-duplicate-names.sql
obsdb < questions/rare_and_interesting_cas.sql
