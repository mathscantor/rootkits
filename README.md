# Rootkits
Contains multiple techniques use in rootkits.
Each sub directory contains custom rootkits that I made over the course of my learning.

## Serial Killer
This is my first rootkit that utitlises ftrace to hook onto `sys_kill` which does the following:

 1. Priviledge Escalation
 2. Hides its presence 
 3. Intercepting /dev/random and /dev/urandom to remove randomness.

 ### Commands
 ```text
kill -60 1 # Sets uid to 0
kill -60 0 # Sets uid to original

kill -61 1 # Hides itself from lsmod
kill -61 0 # Shows itself in lsmod

kill -62 1 # Activates randomness
kill -62 0 # Deactivates randomness
 ```
