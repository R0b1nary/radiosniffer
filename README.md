# radiosniffer
Modern laptops come with various interfaces. Wifi and Bluetooth are commonly provided. The idea of radiosniffer is a tool to sniff for wifi and bluetooth devices with "onboard equipment". Therefore, it could be helpful for lightweight security evaluations or simply satisfaction of curiosity. While the features aren't new, radiosniffer provides:
* setup of sniffing environment (especially wifi)
* wifi channel hopping
* inclusion of beacon frames
* vendor lookup
* automatic restoration for normal operation (linked to ctrl-c)
* summary of results while running and after (comprehensive result file)

Radiosniffer only works under Linux. It is written and tested under Mint 18 on an Asus UX303LN.

##Requirements
The used libraries should be standard except for **pybluez** (pip) and **Scapy** (python-scapy). Additionally, airmon-ng of the **aircrack-ng** suite is used.
The script expects a MAC-vendor lookup file (standards-oui.ieee.org/oui.txt) in a directory named "vendors".

##Result Example
###Online
```
Test
```
###Offline
```
SUMMARY FOR WIFI
scanned channels:32	received beacons:57	received probe requests:2

-----results for beacons/access points-----
Channel | Frequency | MAC Address       | Vendor     | SSID
      1 | 2.412     | 40:16:7e:a2:bd:12 | ASUSTek    | Weltreise
      2 | 2.417     | 40:16:7e:a2:bd:12 | ASUSTek    | Weltreise
                    | 1c:c6:3c:29:c7:c6 | Arcadyan   | EasyBox-29C752
      3 | 2.422     | 1c:c6:3c:29:c7:c6 | Arcadyan   | EasyBox-29C752
      4 | 2.427     | 1c:c6:3c:29:c7:c6 | Arcadyan   | EasyBox-29C752
      5 | 2.432     | 44:32:c8:9c:22:dc | Technicolo | MDCC_00997327500612
      6 | 2.437     | 44:32:c8:9c:22:dc | Technicolo | MDCC_00997327500612
                    | 38:10:d5:81:e9:63 | AVM        | FRITZ!Box 7412
      7 | 2.442     | 44:32:c8:9c:22:dc | Technicolo | MDCC_00997327500612
      8 | 2.447     | 
      9 | 2.452     | c0:25:06:51:80:b5 | AVM        | kluk
     10 | 2.457     | c0:25:06:51:80:b5 | AVM        | kluk
                    | fc:94:e3:02:61:aa | Technicolo | MDCC_00951225600049
     11 | 2.462     | 8c:04:ff:bc:d3:a8 | Technicolo | MDCC_00951322202941
                    | fc:94:e3:02:61:aa | Technicolo | MDCC_00951225600049
                    | c0:25:06:51:80:b5 | AVM        | kluk
     12 | 2.467     | fc:94:e3:02:61:aa | Technicolo | MDCC_00951225600049
                    | 8c:04:ff:bc:d3:a8 | Technicolo | MDCC_00951322202941
     13 | 2.472     | 
     36 | 5.18      | 
     40 | 5.2       | 
     44 | 5.22      | 
     48 | 5.24      | 
     52 | 5.26      | 
     56 | 5.28      | 
     60 | 5.3       | 
     64 | 5.32      | 
    100 | 5.5       | 
    104 | 5.52      | 
    108 | 5.54      | 
    112 | 5.56      | 
    116 | 5.58      | 
    120 | 5.6       | 
    124 | 5.62      | 
    128 | 5.64      | 
    132 | 5.66      | 
    136 | 5.68      | 
    140 | 5.7       | 

-----results for probe requests/devices-----
MAC Address       | Vendor     | SSID                       | Channel | Frequency
80:56:f2:a0:0a:7f | Hon        |                            |       8 | 2.447    


SUMMARY FOR BLUETOOTH
received inquiry results:4 	device count:1
MAC Address       | Vendor           | Device Name       | Linked Wifi Device
00:9e:c8:52:14:ad | Xiaomi           | MiBOX3            | 
```
