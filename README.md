# WireEye
<p align="center">
    <img src="https://github.com/PlatinumVoyager/WireEye/assets/116006542/c75953b6-3d82-4372-ae36-ea62f4d3bb7d" wdith=250 height=250>
</p>
<p align="center"><i>"Gaze into the Abyss, and get lost in the data stream."</i></p>
<br/>

### UPDATE: ~~This framework is under active development and will be released in the future.~~ 

> [!NOTE]
You can obtain/use the extension modules to WireEye via <a href="https://github.com/PlatinumVoyager/WirelessAdvocate"/>WirelessAdvocate</a>

[![PlatinumVoyager - WireEye](https://img.shields.io/static/v1?label=PlatinumVoyager&message=WireEye&color=blue&logo=github)](https://github.com/PlatinumVoyager/WireEye "Go to GitHub repo")
[![stars - WireEye](https://img.shields.io/github/stars/PlatinumVoyager/WireEye?style=social)](https://github.com/PlatinumVoyager/WireEye)
[![forks - WireEye](https://img.shields.io/github/forks/PlatinumVoyager/WireEye?style=social)](https://github.com/PlatinumVoyager/WireEye)

### Toolset for 802.11/LAN reconnaissance across remote and local networks.
WireEye (Wireless Eye) is a 802.11 a/b/g/n wireless protocol analyzer written in Python3 built to capture and dissect 802.11 probe requests, responses, along with the wireless beacon frames deployed by remote access points when advertising their SSID, cipher, wireless capabilities, etc.


## Requirements:
1. A working network adapter that is capable of supporting the following **_management modes_**
for the targeted NIC (*Network Interface Card*):

    - _Monitor_ - allows a computer with a wireless network interface controller (WNIC) to monitor all traffic received on a wireless channel.

2. [Scapy](https://scapy.net/) 
<img src="https://scapy.readthedocs.io/en/latest/_images/scapy_logo.png" width="250">

A python program that enables the user to send, sniff and dissect and forge network packets.

- Installation (Python 3.10):
    - `$(which python3) -m pip install scapy`
<br/>

## Basic Usage:
`$(which python3) wireEye.py --help` 

![image](https://github.com/PlatinumVoyager/WireEye/assets/116006542/71263f22-466f-431a-aa05-471dac0e9bda)

_The first early development files for the WireEye (Wireless Eye) network information gathering submodules for the Python3.10 and C counterparts have been completed. The source code for all static files developed ending in ".c" will be posted at a later date. Stand by._
