# cpp-syn-scan-network
C++ program to scan if some ports are open by sending SYN packets to all IP(s) in a network

A simple tool to scan target hosts for open ports. Uses [libtins](https://github.com/mfontanini/libtins), C++ network packet sniffing and crafting library.

## Usage
Need root permission
```
$ make
# ./syn-scan-network 
Usage: ./syn-scan-network <IP/CIDR> <Port1,Port2,...>
Example:
	./syn-scan-network 166.104.0.0/16 80,443,8080
	./syn-scan-network 35.186.153.3 80,443,8080
	./syn-scan-network 166.104.177.24 80
```

## Example
```
$ sudo ./syn-scan-network 35.186.153.3 80,443,8080
Running on interface: eno1
SYN scan [35.186.153.3]:[80,443,8080]
1 host(s): 35.186.153.3 -> 35.186.153.3

35.186.153.3 (arzhon.id)		Port: 443 open
35.186.153.3 (arzhon.id)		Port: 80 open

Total open hosts: 1 host(s)
Scan duration: 0 hour(s) 0 min(s) 1.0573 sec(s)


$ sudo ./syn-scan-network 166.104.96.13/30 80,8080
Running on interface: eno1
SYN scan [166.104.96.13/30]:[80,8080]
4 host(s): 166.104.96.13 -> 166.104.96.14

166.104.96.13 (hmcgw.hanyang.ac.kr)		Port: 80 open
166.104.96.14 (hmcmail.hanyang.ac.kr)		Port: 80 open

Total open hosts: 2 host(s)
Scan duration: 0 hour(s) 0 min(s) 1.0326 sec(s)
```

## Preview
![Screenshot](screenshots/screenshot01.png?raw=true "Screenshot")

## Used Compiler
```
$ g++ --version
g++ (GCC) 7.3.1 20180312
Copyright (C) 2017 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
```
