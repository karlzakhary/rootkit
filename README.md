# Linux rootkit:
________________
The module was prepared to operate on kernel 4.4.

* To insert the module and start:
```
sudo apt update  
sudo apt install build-essential  
make  
gcc -o client client.c
insmod rootkit.ko
./client
```
* How to use compiled client:
```
./client [-s PID_TO_HIDE] [-h PID_TO_UNHIDE] [-c]  

[-c] hide current process  
[-s] hide PID_TO_HIDE  
[-h] unhide PID_TO_UNHIDE  

```
Demo + Howto
------------

[![Rootkit Demo](http://img.youtube.com/vi/xDz88j4SEJY/0.jpg)](https://youtu.be/xDz88j4SEJY)

Project Contributors
--------------------
* Michael Sherif
* Carol Emad
* Ahmed Houssam
* Mohamed Maged
* Karl Maged
