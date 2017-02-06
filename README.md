# radiosniffer
Modern laptops come with various interfaces. Wifi and Bluetooth are commonly provided. The idea of radiosniffer is a tool to sniff for wifi and bluetooth devices with "onboard equipment". Therefore, it could be helpful for lightweight security evaluations or simply satisfaction of curiosity. While the features aren't new, radiosniffer provides:
* setup of sniffing environment (especially wifi)
* wifi channel hopping
* inclusion of probe requests
* vendor lookup
* automatic restoration for normal operation (linked to ctrl-c)
* summary of results while running and after (comprehensive result file)

Radiosniffer only works under Linux. It is written and tested under Mint 18 on an Asus UX303LN.

##Requirements
The used libraries should be standard except for **pybluez** (pip) and **Scapy** (python-scapy). Additionally, airmon-ng of the **aircrack-ng** suite is used.
The script expects a MAC-vendor lookup file (standards-oui.ieee.org/oui.txt) in a directory named "vendors".

##Result Examples
###Online
```
Wifi channel  104 (5.52   GHz) | Beacons: 64    | Requests: 23

Last 5 Beacons:
CH#10  -> c0:25:06:51:80:b5 (AVM)        Guests
CH#10  -> fc:94:e3:02:61:aa (Technicolo) MDCC_00951225600049
CH#11  -> 8c:04:ff:bc:d3:a8 (Technicolo) MDCC_00951322202941
CH#11  -> fc:94:e3:02:61:aa (Technicolo) MDCC_00951225600049
CH#12  -> fc:94:e3:02:61:aa (Technicolo) MDCC_00951225600049
Last 5 Probe Requests:
CH#3   -> c0:ee:fb:58:7d:f6 (OnePlus)
CH#6   -> c0:ee:fb:58:7d:f6 (OnePlus)    
CH#7   -> c0:ee:fb:58:7d:f6 (OnePlus)     

_____________________________________________________________________________________________
Bluetooth
Last 5 Inquiry Results
MiBOX3     - 00:9e:c8:52:14:ad (Xiaomi)
OnePlus X  - c0:ee:fb:58:7d:f6 (OnePlus)




```
###Offline
```
SUMMARY FOR WIFI
scanned channels:32	received beacons:1760	received probe requests:369

-----results for beacons/access points-----
Channel | Frequency | MAC Address       | Vendor     | SSID
      1 | 2.412     | 
      2 | 2.417     | 
      3 | 2.422     | 
      4 | 2.427     | 
      5 | 2.432     | 90:f6:52:e6:61:8c | TP-LINK    | 
      6 | 2.437     | 00:0c:e6:f2:50:cc | Meru       | IPTLF
                    | 00:0c:e6:f2:37:93 | Meru       | 
                    | 00:0c:e6:f2:97:cf | Meru       | AIRPORT
                    | 00:0c:e6:f2:17:eb | Meru       | OPERA
                    | 00:0c:e6:f2:4c:e8 | Meru       | eduroam
                    | 90:f6:52:e6:61:8c | TP-LINK    | 
      7 | 2.442     | 
      8 | 2.447     | 
      9 | 2.452     | 
     10 | 2.457     | 
     11 | 2.462     | 
     12 | 2.467     | 
     13 | 2.472     | 
     36 | 5.18      | 00:0c:e6:f2:45:06 | Meru       | AIRPORT
                    | 00:0c:e6:f2:b7:0d | Meru       | OPERA
                    | 00:0c:e6:f2:a5:8b | Meru       | eduroam
                    | 00:0c:e6:f2:95:9a | Meru       | 
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
08:70:45:c6:0b:8a | Apple      |                            |       1 | 2.412    
                               | AIRPORT                    |       1 | 2.412    
                               | AIRPORT                    |       3 | 2.422    
                               | AIRPORT                    |       6 | 2.437    
                               | AIRPORT                    |      11 | 2.462    
30:75:12:b6:9b:6a | Sony       | NextGenTel_BA              |       1 | 2.412    
                               |                            |       1 | 2.412    
                               | NextGenTel_BA              |       2 | 2.417    
                               |                            |       2 | 2.417    
                               |                            |       8 | 2.447    
                               | NextGenTel_BA              |       8 | 2.447    
                               | NextGenTel_BA              |      36 | 5.18     
                               |                            |      36 | 5.18     
f0:25:b7:05:e9:8b | SAMSUNG    |                            |       1 | 2.412    
30:75:12:dc:99:4d | Sony       | netgeat                    |       1 | 2.412    
                               |                            |       1 | 2.412    
                               | netgeat                    |       4 | 2.427
c0:ee:fb:58:7d:f6 | OnePlus    |                            |       3 | 2.422    
                               |                            |       6 | 2.437    
                               |                            |       7 | 2.442    


SUMMARY FOR BLUETOOTH
received inquiry results:25 	device count:2
MAC Address       | Vendor           | Device Name       | Linked Wifi Device
00:9e:c8:52:14:ad | Xiaomi           | MiBOX3            | 
c0:ee:fb:58:7d:f6 | OnePlus          | OnePlus X         | yes
```

##TODO
- encryption of wifi APs
- option for efficient channel hopping (unused channels are ignored after n loops)
- option for csv output
- adaption for window size
- fault tolerance for missing interfaces (bt/wifi)
- setup.py
