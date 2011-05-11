#!/usr/bin/env python
import MySQLdb

try:    from db_private import DB_USER
except: DB_USER = "root" 

try:    from db_private import DB_PASS
except: DB_PASS = "root"                # change this for your local setup

try:    from db_private import DB_NAME  
except: DB_NAME = "observatory"

def dbconnect():
  db = MySQLdb.connect(user=DB_USER, passwd=DB_PASS, db=DB_NAME)
  dbc = db.cursor()
  return db,dbc
