S syn port scanner

S is a very fast port scanner 
it use the syn half connect port scan method
it can scann a range ip or a range port or serval ip or serval port at on time 
just type 'make' then you will get it

Usage:   s [Ip String] Ports [/Save]
Example: s 12.12.12.12-12.12.12.254 80
Example: s 12.12.12.12 1-65535
Example: s 12.12.12.12/24 1-65535
Example: s 12.12.12.12-12.12.12.254 21,80,3389
Example: s 12.12.12.12,12.12.12.122 21,80,3389-22233  /Save
