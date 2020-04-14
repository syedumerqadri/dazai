![](https://github.com/syedumerqadri/dazai/blob/master/Untitled.jpg)
![](https://github.com/syedumerqadri/dazai/blob/master/ss.png)
#                               Dazai v1.0 | Android Forensics Tool 
## This is basic android forensics tool written in python it's use adb shell to intract with device and grab information about it

## Features:

          [1] List supported file system
          [2] List Mount Point
          [3] Create Device Backup
          [4] Pull system
          [5] Pull sdcard
          [6] Dump message buffer of the kernel
          [7] Applications Memory Usage
          [8] CPU Usage
          [9] Dump Running Services
          [10] Dump Wifi Info
          [11] Battery Info
          [12] Dump Data Sync
          [13] Directory Info 

and using special command "dazai" you can create a full report in HTML format

## Installation:
1. chmod +x setup.sh
2. ./setup.sh

## Usage:
1. Turn on ADB bridge on your android device
2. connect it with usb and turn on debugging mode
3. Use the tool with command:
   python dazai.py

## Platform:
Curruntly it's only suppourted on Linux
