import signal
import subprocess
import time
import sys
import os
import optparse
import re
import logging
# Silence Scapy IPv6 message at runtime
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from termcolor import colored
from bluetooth import *
import curses
from threading import Thread


WIFI_IFACE = ''
WIFI_MON = ''
VENDORS = None
KILLED_PROC = []
WIFI_CHS = None
WIFI_INFO = None
BT_INFO = None
THREAD_BT = None
RUN = True
STDSCR = None
STDSCR_X = None
STDSCR_Y = None


class Vendors:
    def __init__(self):
        self.macs = []
        self.vendors = []

    def read_file(self, path):
        file = open(path, 'r')
        for line in file:
            if re.match(".*base 16.*", line):
                mac = re.findall("([A-F0-9]+) +", line)
                if len(mac) > 0:
                    self.macs.append(mac[0].lower())
                    firstname = re.findall("\(base 16\)\s+([^\n,. ]+)[\n,. ]?.*", line) # TODO newline mit Joker fuer alle Zeilenumbrueche ersetzen
                    if len(firstname) > 0:
                        self.vendors.append(firstname[0])
                    else:
                        print_error("could not find vendor name for corresponding MAC address (" + mac[0] + ")")
                        sys.exit(1)

    def get_name(self, mac):
        mac = mac.lower()
        vendid = mac[:]
        vendid = vendid.replace(":", "")
        vendid = vendid[0:6]
        for idx, smac in enumerate(self.macs):
            if smac == vendid:
                return self.vendors[idx]
        return "unknown"


class Interfaces:
    def __init__(self):
        self.descriptions = []
        self.vendors = []
        self.products = []
        self.interfaces = []
        self.businfo = []
        proc = subprocess.Popen(["lshw -class network"], shell=True, stdout=subprocess.PIPE)
        output = proc.stdout.read()
        for line in output.split("\n"):
            if re.match(".*\*\-network", line):
                self.descriptions.append("")
                self.vendors.append("")
                self.products.append("")
                self.businfo.append("")
                self.interfaces.append("")
            description_re = ".*description: (.*)"
            if re.match(description_re, line):
                self.descriptions[-1] = re.findall(description_re, line)[0]
            vendor_re = ".*vendor: (.*)"
            if re.match(vendor_re, line):
                self.vendors[-1] = re.findall(vendor_re, line)[0]
            product_re = ".*product: (.*)"
            if re.match(product_re, line):
                self.products[-1] = re.findall(product_re, line)[0]
            businfo_re = ".*bus info: (.*)@.*"
            if re.match(businfo_re, line):
                self.businfo[-1] = re.findall(businfo_re, line)[0]
            interface_re = ".*logical name: (.*)"
            if re.match(interface_re, line):
                self.interfaces[-1] = re.findall(interface_re, line)[0]

    def filterwifi(self):
        i = 0
        while i < len(self.interfaces):
            if self.descriptions[i] != "Wireless interface":
                del self.descriptions[i]
                del self.vendors[i]
                del self.products[i]
                del self.businfo[i]
                del self.interfaces[i]
            else:
                i += 1

    def show(self):
        for i in range(len(self.interfaces)):
            if self.vendors[i] == "" and self.products[i] == "":
                print str(i + 1) + ".", self.descriptions[i], "@"+self.businfo[i], "(" + self.interfaces[i] + ")"
            else:
                print str(i + 1) + ".", self.vendors[i], self.products[i], "@"+self.businfo[i],"(" + self.interfaces[i] + ")"

    def getinterface(self, index):
        return self.interfaces[index]

    def checkindex(self, index):
        if index >= 0 and index < len(self.interfaces):
            return True
        else:
            return False

    def getsize(self):
        return len(self.interfaces)


class Channels:
    def __init__(self, interface):
        proc = subprocess.Popen(["iwlist " + interface + " channel"], shell=True, stdout=subprocess.PIPE)
        output = proc.stdout.read()
        channels = re.findall("\s(Channel [0-9]+ : [0-9]+\.[0-9]+ GHz)\n", output)
        self.num = []
        self.freq = []
        self.aps = [] #access point info per channel
        self.devices = [] #device info per channel
        self.inuse = [] #boolean for detected traffic on channel
        for channel in channels:
            self.num.append(int(re.findall("Channel ([0-9]+) :", channel)[0]))
            self.freq.append(re.findall("([0-9]+\.[0-9]+) GHz", channel)[0])
            #print self.num, self.freq
            self.aps.append(list())
            self.devices.append(list())
            self.inuse.append(False)
        self.channel_idx = {val: idx for idx, val in enumerate(self.num)}
        self.current_chidx = 0

    def get_num(self):
        return self.num[self.current_chidx]

    def get_freq(self):
        return self.freq[self.current_chidx]

    def add_ap(self, mac, ssid, encryption):
        new_ap = AP(mac.lower(), ssid, encryption)
        for ap in self.aps[self.current_chidx]:
            if ap.matches(new_ap):
                return False
        self.aps[self.current_chidx].append(new_ap)
        return True

    def add_dev(self, mac, ssid):
        new_dev = Device(mac=mac.lower(), ssid=ssid)
        if new_dev not in self.devices[self.current_chidx]:
            self.devices[self.current_chidx].append(new_dev)
            return True
        else:
            return False

    def set_chactive(self):
        self.inuse[self.current_chidx] = True

    def get_chactivity(self):
        return self.inuse[self.current_chidx]


class AP:
    def __init__(self, mac, ssid, encryption): #TODO encryption von APs auslesen und speichern
        self.mac = mac
        self.ssid = ssid
        self.encryption = encryption

    def matches(self, ap_obj):
        if self.mac == ap_obj.mac and self.ssid == ap_obj.ssid and self.encryption == ap_obj.encryption:
            return True
        else:
            return False


class Device:
    def __init__(self, mac="", ssid="", btname="", linked=False):
        self.mac = mac
        self.ssid = ssid
        self.btname = btname
        self.linked = linked


class WifiStatus:
    def __init__(self):
        self.beacon_count = 0
        self.request_count = 0
        news_size = 5 # number of last ap/device entries for status
        self.new_aps = [""] * news_size
        self.new_devs = [""] * news_size

    def set_ap(self, channel, mac, vendor, ssid):
        self.__set_info__("CH#"+self.__format_channel__(channel)+" -> "+mac+self.__format_vendor__(vendor)+ssid, self.new_aps)

    def set_dev(self, channel, mac, vendor, ssid):
        self.__set_info__("CH#"+self.__format_channel__(channel)+" -> "+mac+self.__format_vendor__(vendor)+ssid, self.new_devs)

    def get_infoblock(self):
        ap_intro = ["Last "+str(len(self.new_aps))+" Beacons:"]
        dev_intro = ["Last " + str(len(self.new_devs)) + " Probe Requests:"]
        return ap_intro + self.new_aps + dev_intro + self.new_devs

    def __format_channel__(self, channel):
        gap = 3 - len(str(channel))
        return str(channel) + " " * gap

    def __format_vendor__(self, vendor):
        length = 10
        if len(vendor) >= length:
            vendor = vendor[0:length]
            return " (" + vendor + ") "
        if len(vendor) < length:
            return " (" + vendor + ") " + " " * (length - len(vendor))

    def __set_info__(self, infostr, infolist):
        if infostr not in infolist:
            if "" not in infolist:
                del infolist[0]
                infolist.append(infostr)
            else:
                for i in range(0, len(infolist)):
                    if infolist[i] == "":
                        infolist[i] = infostr
                        break


class BTstatus:
    def __init__(self):
        self.device_count = 0
        news_size = 5 # number of last device entries for status
        self.new_devs = [""] * news_size
        self.devices = []
        self.inquiry_count = 0

    def add_dev(self, name, mac):
        new_dev = Device(btname=name, mac=mac)
        self.inquiry_count += 1
        already_in = False
        for dev in self.devices:
            if new_dev.btname == dev.btname and new_dev.mac == dev.mac:
                already_in = True
                break
        if not already_in:
            self.devices.append(new_dev)
            return True
        else:
            return False

    def get_infoblock(self):
        dev_intro = ["Last " + str(len(self.new_devs)) + " Inquiry Results"]
        return dev_intro + self.new_devs

    def __format_name__(self, name):
        length = 10
        if len(name) >= length:
            name = name[0:length]
            return name + " - "
        if len(name) < length:
            return name + " " * (length - len(name)) + " - "

    def set_dev(self, name, mac, vendor):
        self.add_dev(name, mac)
        infostr = self.__format_name__(name)+mac+" ("+vendor+")"
        if infostr not in self.new_devs:
            if "" not in self.new_devs:
                del self.new_devs[0]
                self.new_devs.append(infostr)
            else:
                for i in range(0, len(self.new_devs)):
                    if self.new_devs[i] == "":
                        self.new_devs[i] = infostr
                        break


def get_wifiinterface():
    all_interfaces = Interfaces()
    all_interfaces.filterwifi()
    if all_interfaces.getsize() > 1:
        if_selection = -1
        while not all_interfaces.checkindex(if_selection - 1):
            print "Available wifi interfaces to listen on"
            all_interfaces.show()
            try:
                if_selection = raw_input("Selection: ")
                if_selection = int(if_selection)
            except ValueError:
                if_selection = -1
        return all_interfaces.getinterface(if_selection - 1)
    else:
        return all_interfaces.getinterface(0)


def setup_wifimonitor():
    global WIFI_MON
    # disconnect wifi interface (error prevention)
    #subprocess.call(["nmcli", "d", "disconnect", WIFI_IFACE])
    # stop network-manager
    print_info("stop network-manager")
    subprocess.call(["service", "network-manager", "stop"])
    proc = subprocess.Popen(["airmon-ng start "+WIFI_IFACE], shell=True, stdout=subprocess.PIPE)
    output = proc.stdout.read()
    WIFI_MON = re.findall(".*\(monitor mode enabled on (.*)\).*", output)[0]
    print_info(WIFI_MON+" created")
    #note processes that could cause trouble
    procs = re.findall("PID\tName(.*\n[0-9]+\t\S+\n)", output, re.DOTALL)[0]
    procs = re.findall("\n*([0-9]+\t\S+)\n*", procs)
    global KILLED_PROC
    for proc in procs:
        id_name = proc.split("\t")
        print_info("kill trouble maker "+id_name[1])
        subprocess.call(["kill", id_name[0]])
        if id_name[1] not in KILLED_PROC:
            KILLED_PROC.append(id_name[1])
    print_info("start sniffing on interface " + WIFI_MON)


def sniffwifi():
    global WIFI_CHS
    WIFI_CHS = Channels(WIFI_MON)
    global WIFI_INFO
    WIFI_INFO = WifiStatus()
    allchs_scanned = False

    while RUN:
        for chan_i in range(0, len(WIFI_CHS.num)):
            if not RUN:
                break
            WIFI_CHS.current_chidx = chan_i
            if WIFI_CHS.get_chactivity() or not allchs_scanned: # TODO skriptparamter einfuegen fuer effective scanning
                subprocess.call(["ifconfig", WIFI_IFACE, "down"])
                proc = subprocess.Popen(["iwconfig " + WIFI_MON + " channel " + str(WIFI_CHS.get_num())], shell=True, stderr=subprocess.PIPE)
                output = proc.stderr.read()
                if re.match(".*error.*", output, re.IGNORECASE):
                    print_error(output)
                    restore()
                    sys.exit(1)
                else:
                    sniff(iface=WIFI_MON, prn=handle_wifipkt, timeout=3, store=0)
                subprocess.call(["ifconfig", WIFI_IFACE, "up"])
                STDSCR.addstr(0, 0, "Wifi channel " + str(WIFI_CHS.get_num()).rjust(4, " ") + " (" + str(WIFI_CHS.get_freq()).ljust(6, " ") + \
                              " GHz) | Beacons: " + str(WIFI_INFO.beacon_count) + "\t| Requests: " + str(WIFI_INFO.request_count))
                STDSCR.clrtoeol()
                STDSCR.refresh()
                print_cursedblock(2, WIFI_INFO.get_infoblock())
                if chan_i == len(WIFI_CHS.num)-1:
                    allchs_scanned = True


def handle_wifipkt(pkt):
    global WIFI_INFO
    global WIFI_CHS
    if pkt.haslayer(Dot11):
        WIFI_CHS.set_chactive()
        # check for access point beacon
        if pkt.haslayer(Dot11Beacon):
            WIFI_INFO.beacon_count += 1
            WIFI_CHS.add_ap(pkt.addr2, pkt.info, "")
            WIFI_INFO.set_ap(WIFI_CHS.get_num(), pkt.addr2, VENDORS.get_name(pkt.addr2), pkt.info)
            #STDSCR.addstr(1, 0, pkt.summary())
        # check for probing of devices
        if pkt.haslayer(Dot11ProbeReq):
            WIFI_INFO.request_count += 1
            WIFI_CHS.add_dev(pkt.addr2, pkt.info)
            WIFI_INFO.set_dev(WIFI_CHS.get_num(), pkt.addr2, VENDORS.get_name(pkt.addr2), pkt.info)
        #STDSCR.refresh()
    #print pkt.summary()


def sniffbt():
    global BT_INFO
    BT_INFO = BTstatus()
    global VENDORS
    STDSCR.addstr(15, 0, "_"*STDSCR_X)
    STDSCR.addstr(16, 0, "Bluetooth")
    STDSCR.refresh()
    while RUN:
        # performs a bluetooth device discovery using the first available bluetooth resource.
        nearby_devices = discover_devices(duration=2, lookup_names=True)
        for mac, name in nearby_devices:
            BT_INFO.set_dev(name, mac.lower(), VENDORS.get_name(mac))
        print_cursedblock(17, BT_INFO.get_infoblock())


def store_results(path):
    file = open(path, 'w')
    file.write("SUMMARY FOR WIFI\n")
    file.write("scanned channels:" + str(len(WIFI_CHS.freq)) + "\treceived beacons:" + str(WIFI_INFO.beacon_count) +
               "\treceived probe requests:" + str(WIFI_INFO.request_count) + "\n\n")
    ###formating results for APs (wifi)
    file.write("-----results for beacons/access points-----\n")
    header = ["Channel", "Frequency", "MAC Address      ", "Vendor    ", "SSID"]
    for idx, item in enumerate(header):
        file.write(item)
        if idx < len(header)-1:
            file.write(" | ")
    file.write("\n")
    for idx, num in enumerate(WIFI_CHS.num):
        file.write(str(num).rjust(len(header[0]), " "))
        file.write(" | ")
        file.write(str(WIFI_CHS.freq[idx]).ljust(len(header[1]), " "))
        file.write(" | ")
        for idxap, ap in enumerate(WIFI_CHS.aps[idx]):
            if idxap > 0:
                file.write("\n".ljust(len(header[0]) + len(header[1]) + 4, " ") + " | ")
            file.write(ap.mac + " | " + VENDORS.get_name(ap.mac)[0:len(header[3])].ljust(len(header[3]), " ") + " | ")
            file.write(ap.ssid)
        file.write("\n")
    ##formating results for requests of devices (wifi)
    file.write("\n-----results for probe requests/devices-----\n")
    header = ["MAC Address      ", "Vendor    ", "SSID                      ", "Channel", "Frequency"]
    for idx, item in enumerate(header):
        file.write(item)
        if idx < len(header)-1:
            file.write(" | ")
    file.write("\n")
    devs_toprint = []
    for idx, devs_per_ch in enumerate(WIFI_CHS.devices):
        for dev in devs_per_ch:
            for btdev in BT_INFO.devices:
                if btdev.mac == dev.mac:
                    btdev.linked = True
                    break
            string_toprint1 = dev.ssid.ljust(len(header[2]), " ")[0:len(header[2])] + " | " + \
                              str(WIFI_CHS.num[idx]).rjust(len(header[3]), " ") + " | " + \
                              WIFI_CHS.freq[idx].ljust(len(header[4]), " ") + "\n"
            already_in = False
            for dev_idx, dev_string in enumerate(devs_toprint):
                if dev_string[0:len(dev.mac)] == dev.mac:
                    already_in = True
                    if devs_toprint[dev_idx].rfind(string_toprint1) == -1:
                        devs_toprint[dev_idx] += " " * (len(header[0]) + len(header[1]) + 3) + " | " + string_toprint1
                    break
            if not already_in:
                string_toprint0 = dev.mac + " | " + VENDORS.get_name(dev.mac).ljust(len(header[1]), " ") + " | "
                devs_toprint.append(string_toprint0 + string_toprint1)
            already_in = False
    for dev_string in devs_toprint:
        file.write(dev_string)
    ##formating results for inquiry results of devices (bluetooth)
    file.write("\n\nSUMMARY FOR BLUETOOTH\n")
    if BT_INFO is None:
        file.write("no interface found")
    else:
        file.write("received inquiry results:"+str(BT_INFO.inquiry_count)+" \tdevice count:"+str(len(BT_INFO.devices))+"\n")
        header = ["MAC Address      ", "Vendor          ", "Device Name      ", "Linked Wifi Device"]
        for idx, item in enumerate(header):
            file.write(item)
            if idx < len(header)-1:
                file.write(" | ")
        file.write("\n")
        for dev in BT_INFO.devices:
            file.write(dev.mac.ljust(len(header[0]), " "))
            file.write(" | ")
            file.write(VENDORS.get_name(dev.mac).ljust(len(header[1]), " "))
            file.write(" | ")
            file.write(dev.btname.ljust(len(header[2]), " "))
            file.write(" | ")
            if dev.linked:
                file.write("yes")
            file.write("\n")
    file.close()


def print_info(line):
    print colored("[+] "+line, "blue", attrs=["bold"])


def print_error(line):
    print colored("[!] " + line, "red", attrs=["bold"])


def print_cursedblock(start_line, linelist):
    y = start_line
    for line in linelist:
        #STDSCR.addstr(y, 0, " " * len(line))
        #STDSCR.clrtoeol()
        STDSCR.addstr(y, 0, line)
        STDSCR.clrtoeol()
        STDSCR.refresh()
        y += 1


def restore(storeit=True):
    global RUN
    RUN = False
    if THREAD_BT is not None:
        THREAD_BT.join()
    # restore terminal configuration (curses)
    curses.echo()
    curses.endwin()
    print "\n"
    #remove monitor interface
    airmon = subprocess.Popen(["airmon-ng stop "+WIFI_MON], shell=True, stdout=subprocess.PIPE)
    output = airmon.stdout.read()
    print_info(WIFI_MON+" removed")
    #restart previously killed processes
    for proc in KILLED_PROC:
        print_info("restart "+proc)
        proc_restart = subprocess.Popen(proc, shell=True, stdout=subprocess.PIPE)
        output = proc_restart.stdout.read()
        line_max = 2
        for line in output.split("\n"):
            if line == "":
                break
            if line_max > 0:
                print line
            line_max -= 1
    #restart network-manager
    print_info("restart network-manager")
    subprocess.call(["service", "network-manager", "start"])
    print_info("some time for restart of processes...")
    time.sleep(3)
    print_info("system status restored")
    if storeit:
        print_info("saving results...")
        store_results("result.txt")
    print_info("exit radiosniffer")


def exit(signum, frame):
    #restore handler
    signal.signal(signal.SIGINT, original_sigint)
    try:
        restore()
        sys.exit(1)
    except KeyboardInterrupt:
        print("Quitting")
        sys.exit(1)
    #signal.signal(signal.SIGINT, exit)


def main():
    parser = optparse.OptionParser('Script must be run as root\nradiosniffer.py -i<interface>')
    parser.add_option("-i", dest="interface", type="string", help="specify interface to listen on (optional)")
    #TODO efficient mode focuses on channels where radiosniffer received frames during the first channel hopping cycle
    #TODO compact mode ignores devices/aps which aren't broadcasting a SSID
    #parser.add_option("-e", dest="efficient", type="string", help="file for mac-vendor mapping (standards-oui.ieee.org/oui.txt)")
    (options, args) = parser.parse_args()
    if not os.geteuid() == 0:
        sys.exit('Script must be run as root')

    global WIFI_IFACE
    if options.interface is None:
        WIFI_IFACE = get_wifiinterface()
    else:
        WIFI_IFACE = options.interface
    #print parser.usage
    #exit(0)

    try:
        global VENDORS
        VENDORS = Vendors()
        vendorfile = os.listdir("vendors")
        if len(vendorfile) == 0 or len(vendorfile) > 1:
            print_error("vendors folder has to contain exactly one file for mac-vendor mapping from standards-oui.ieee.org/oui.txt")
            exit(0)
        VENDORS.read_file("vendors/" + vendorfile[0])

        setup_wifimonitor()
        global STDSCR
        STDSCR = curses.initscr()
        global STDSCR_Y
        global STDSCR_X
        STDSCR_Y, STDSCR_X = STDSCR.getmaxyx()
        min_y = 25
        min_x = 80
        if STDSCR_X < min_x or STDSCR_Y < min_y:
            print_error("window is to small (min. x=" + str(min_x) + ", y=" + str(min_y) + ")") # TODO use addnstr and global x
            #  values and option to turn of status screen
            restore(storeit=False)
            sys.exit(1)
        else:
            curses.noecho()
            global RUN
            RUN = True
            global THREAD_BT
            THREAD_BT = Thread(target=sniffbt)
            THREAD_BT.start()
            sniffwifi()
            restore()
    except Exception, e:
        # restore terminal configuration (curses)
        curses.echo()
        curses.endwin()
        print_error(str(e))
        restore()
        sys.exit(1)


if __name__ == '__main__':
    # store the original SIGINT handler
    original_sigint = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, exit)
    main()
