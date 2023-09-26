import logging
import argparse

from sys import exit
from time import sleep
from datetime import datetime
from signal import signal, SIGINT
from subprocess import call, PIPE

# Usage python3.10 wireEye.py -h

'''
    - finish channel hopping functionality
    - visualize data with matplotlib
    - implement GPS functionality and mapping with GPSD and leaf
        would need to store wireless AP as dictionary, AP_NAME, LOCATION (GPS COORDINATES) then pass this data to folium
    
        - would need to get BASE COORDINATES
          * if operator chooses a command line option for this press ENTER to store current coordinates as the BASE COORDINATES
'''

# Wireless Eye (WireEye)

# set logging level for scapy
logging.getLogger("scapy").setLevel(logging.CRITICAL)

from scapy.all import sniff
from scapy.layers import dot11

TAG_IDENTIFIER = ""
WIREEYE_VERSION = "v0.5.0"

# view 802.11 probe request/response
# view 802.11 beacon frames (AP's advertising themselves)

ST_TIME = None
INTERRUPT_ID = None

known_bssids = []
hidden_ssids = []

TOTAL_PROBE_REQUESTS = 0
TOTAL_PROBE_RESPONSES = 0

ESCAPE = "\033[0;m"

GREY = "\033[90;3m"
BOLD_GREY = "\033[90;1m"
BLUE = "\033[0;34m"
BOLD_RED = "\033[31;1m"
BOLD_YELLOW = "\033[93;1m"
YELLOW = "\033[0;33m"

GREEN = "\033[0;32m"
BRIGHT_GREEN = "\033[92;1m"
FAINT_GREEN = "\033[32;2m"
BOLD_GREEN = "\033[32;1m"

# ANSI ESCAPE SEQUENCES
RA_POOR = f"{BOLD_RED}POOR{ESCAPE}" # red
RA_FAIR = f"{BOLD_YELLOW}FAIR{ESCAPE}" # yellow
RA_AVERAGE = f"{GREEN}AVERAGE{ESCAPE}" # green
RA_EXCELLENT = f"{BRIGHT_GREEN}EXCELLENT{ESCAPE}" # blue

probe_request_run_count = 0
probe_response_run_count = 0

# pretty sure probe responses are unicast
def probe_response_handler(pR80211_frame):
    global INTERRUPT_ID, TOTAL_PROBE_RESPONSES

    # print("## PROBE RESPONSE HANDLER: Listening...")

    if pR80211_frame.haslayer(dot11.Dot11ProbeResp):
        TOTAL_PROBE_RESPONSES = TOTAL_PROBE_RESPONSES + 1

        if probe_response_run_count == 0:
            INTERRUPT_ID = 2
            probe_response_run_count + 1
            
        elif probe_response_run_count == 1:
            pass

        poas = datetime.now()
        packet_ts = f"{poas.month}-{poas.day}-{poas.year} {poas.hour}:{poas.minute}:{poas.second}"

        sta_addr_str = pR80211_frame[dot11.Dot11].addr1 # dst (wireless STA)
        sta_addr = f"{GREY}{sta_addr_str.upper()}{ESCAPE}" # dst (wireless STA)

        ap_addr = f"{GREEN}{(pR80211_frame[dot11.Dot11].addr2).upper()}{ESCAPE}" # source address (AP (real || rogue))

        ap_ssid_str = pR80211_frame[dot11.Dot11Elt].info
        ap_ssid = f"{FAINT_GREEN}({ap_ssid_str.decode()}){ESCAPE}"

        print(f"[{packet_ts}] WireEye::probe_resp #{TOTAL_PROBE_RESPONSES} {ap_addr} {ap_ssid} responds to wireless STA => {sta_addr}")

        # need a database to store data
        # if an area is frequented we can use that data to point which devices are connected to which networks and sending probes, etc


def probe_request_handler(pr80211_frame):
    global INTERRUPT_ID, TOTAL_PROBE_REQUESTS

    if pr80211_frame.haslayer(dot11.Dot11ProbeReq):
        print(TOTAL_PROBE_REQUESTS)
        TOTAL_PROBE_REQUESTS = TOTAL_PROBE_REQUESTS + 1

        # only set 1 time per execution. Log 10,000 frames and set it 10,000 times? No.
        if probe_request_run_count == 0: # first packet
            INTERRUPT_ID = 1
            probe_request_run_count + 1

        elif probe_request_run_count == 1:
            pass

        # we need to log the MAC of the device sending the probe request and capture all other unique SSID's that
        # are seen with the same MAC

        poas = datetime.now()
        packet_ts = f"{poas.month}-{poas.day}-{poas.year} {poas.hour}:{poas.minute}:{poas.second}"

        dst_addr = pr80211_frame[dot11.Dot11].addr1 # dst (AP BSSID)
        dev_addr = pr80211_frame[dot11.Dot11].addr2 # source address

        if str(dst_addr).upper() == "FF:FF:FF:FF:FF:FF":
            # probe request was sent to broadcast, not directed to a particular SSID
            ssid_head = f"{GREY}{dev_addr.upper()}{ESCAPE}"
            ssid_tail = f"{FAINT_GREEN}(BROADCAST){ESCAPE}"

        else: # targeted probe request (device has authenticated and associated to the wireless AP before)
            ssid_head = f"{BOLD_GREY}{dev_addr.upper()}{ESCAPE}"
            ssid_tail = f"{BOLD_GREEN}({dst_addr.upper()}){ESCAPE}"

        # a try inside of a try, I did not try to make this any cleaner.
        try:
            sta_target_ssid = pr80211_frame[dot11.Dot11Elt].info
        
        except IndexError:
            sta_target_ssid = "Unknown"
        
        else:
            net_res = ""

            # detect devices connected to hidden ssids
            if len(sta_target_ssid) == 0:
                sta_target_ssid = "______"
                net_res = "HIDDEN SSID"

            else:
                try:
                    sta_target_ssid = f"{GREEN}{sta_target_ssid.decode()}{ESCAPE} {ssid_tail}"
                
                except UnicodeDecodeError:
                    sta_target_ssid = f"{BOLD_RED}DECODE-ERROR{ESCAPE}"

                else:
                    net_res = "SSID"

                    print(f"[{packet_ts}] WireEye::probe_req #{TOTAL_PROBE_REQUESTS} => Wireless STA: {ssid_head} has {net_res} {sta_target_ssid} as probe target")

beacon_run_count = 0

ACCESS_POINT_CURRENT = 0


def beacon_frame_handler(w80211_frame):
    global INTERRUPT_ID, ACCESS_POINT_CURRENT

    # to prevent setting INTERRUPT_ID on every function call
    if beacon_run_count == 0: # first packet captured
        INTERRUPT_ID = 0
        beacon_run_count + 1

    elif beacon_run_count == 1:
        pass

    # type == 0 (MANAGMENT) | subtype == 8 (BEACON)
    if w80211_frame.haslayer(dot11.Dot11Beacon) and w80211_frame.type == 0 and w80211_frame.subtype == 8:
        # POAS - Packet On Arrival String
        poas = datetime.now()
        packet_ts = f"{poas.month}-{poas.day}-{poas.year} {poas.hour}:{poas.minute}:{poas.second}"

        # 802.11 beacon interval (DEFAULT=100 ms)
        # ap_beacon_int = w80211_frame[dot11.Dot11Beacon].beacon_interval 
        access_point = w80211_frame.addr2

        if access_point not in known_bssids:
            ACCESS_POINT_CURRENT = ACCESS_POINT_CURRENT + 1

            known_bssids.append(access_point)

            # AP SIGNAL STRENGTH
            ap_sig_rating = "" # empty
            ap_sig_str = str(w80211_frame[dot11.RadioTap].dBm_AntSignal)
            
            # need to write a timed function that will switch to different wireless frequencies (channels)
            # the current wic channel is set to 1 (default) set with -c || --channel
            ap_channel = w80211_frame[dot11.RadioTap].channel
            ap_sig_strength = ap_sig_str[1:]

            # ugly way of checking for all ranges
            if int(ap_sig_strength) in range(0, 56): # EXCELLENT
                ap_sig_rating = RA_EXCELLENT

            elif int(ap_sig_strength) in range(57, 68): # AVERAGE
                ap_sig_rating = RA_AVERAGE

            elif int(ap_sig_strength) in range(69, 79): # FAIR
                ap_sig_rating = RA_FAIR

            elif int(ap_sig_strength) in range(80, 100): # POOR
                ap_sig_rating = RA_POOR

            ap_bssid = w80211_frame[dot11.Dot11].addr2 # MAC (src)
            ap_ssid = w80211_frame[dot11.Dot11Elt].info # b'' Service Set Identifier

            if len(ap_ssid) < 1:
                TAG_IDENTIFIER = f"{GREY}HIDDEN{ESCAPE}"
                ap_ssid = "______" # HIDDEN

                hidden_ssids.append(access_point)

            else:
                TAG_IDENTIFIER = "Wireless"
                ap_ssid = f"{GREEN}{ap_ssid.decode()}{ESCAPE}"

                # need to add a feature that matches the ap_bssid against a database of manufacturer OUI's

            print(f"[{packet_ts}] WireEye::dot11_spy >> {TAG_IDENTIFIER} Access Point: {ap_ssid} => {ap_bssid.upper()} CH#{ap_channel} (-{ap_sig_strength} dBm | RA: {ap_sig_rating})")


def interrupt_handler(sig, frame):
    # time elapsed
    t_end = datetime.now()
    diff = t_end - ST_TIME

    sid = 24 * 60 * 60
    div = divmod(diff.days * sid + diff.seconds, 60)

    t_str = f"\nTime Elapsed: {GREEN}{div[0]}{ESCAPE} minutes, {GREEN}{div[1]}{ESCAPE} seconds..."

    # beacon frames (subtype 8)
    if INTERRUPT_ID == 0:
        # num visible, num hidden, num total
        print(f"\n\n{GREEN}{len(known_bssids) - len(hidden_ssids)}{ESCAPE} AP\'s in total were visible.\n{YELLOW}{len(hidden_ssids)}{ESCAPE} of which are hidden.\n{BLUE}{len(known_bssids)}{ESCAPE} AP\'s discovered.")
        print(t_str)

    # probe requests
    elif INTERRUPT_ID == 1:
        print(f"\n{GREEN}{TOTAL_PROBE_REQUESTS}{ESCAPE} 802.11 probe requests were visible.")
        print(t_str)

    # probe responses
    elif INTERRUPT_ID == 2:
        print(f"\n{GREEN}{TOTAL_PROBE_RESPONSES}{ESCAPE} 802.11 probe responses were visible.")
        print(t_str)

    exit(0)

if __name__ == "__main__":
    signal(signalnum=SIGINT, handler=interrupt_handler)

    TIME_WAIT = 2 

    # setup opts
    formatter = lambda prog: argparse.HelpFormatter(prog, max_help_position=52)

    parser = argparse.ArgumentParser(prog="WIREEYE", description="IEEE 802.11 Wireless Protocol Analyzer/Framework", 
                formatter_class=formatter)

    # change from WIC to INTERFACE

    parser.add_argument("--wic", "-i", help="host wireless interface card to use", required=True, metavar="INTERFACE")
    parser.add_argument("--channel", "-c", help="set the wireless interface card to specified channel (iwconfig)", required=False)
    parser.add_argument("--bframes", "-b", help="view wireless beacon frames from surrounding access points", action="store_true", required=False)
    parser.add_argument("--preq", "-r", help="show probe requests from other wireless stations", action="store_true", required=False)
    parser.add_argument("--presp", "-R", help="show probe responses from wireless access points to other wireless stations", action="store_true", required=False)
    
    # parser.add_argument("--hop", "-H", help="initiate channel hopping on the target WIC (1-11)", action="store_true", required=False)
    '''
        for channel hopping, need to time the original beacon frame function 
        then switch channels, 1 - 11, 11 - 1, until SIGINT by operator
    '''

    args = parser.parse_args()

    print(f"** WireEye - IEEE 802.11 Wireless Protocol Analyzer {WIREEYE_VERSION} (python3.10) \033[0;32mRunning\033[0;m...\n")

    interface = args.wic # network interface card

    # check for channel being set
    if args.channel != None:
        print(f"[{BLUE}*{ESCAPE}] Setting channel priority to: {GREEN}{args.channel}{ESCAPE}")
        
        try:
            call(f"iwconfig {interface} channel {args.channel}", shell=True, stdout=PIPE)
        
        except Exception as err:
            print(f"Failed to set target channel! Error: {BOLD_RED}{err}{ESCAPE}")
            exit(1)

    if args.bframes:
        ST_TIME = datetime.now()
        print(f"[{BLUE}*{ESCAPE}] Monitoring 802.11 Beacon Frames...\n")
        sleep(TIME_WAIT)

        sniff(iface=interface, prn=beacon_frame_handler)

    elif args.preq:
        ST_TIME = datetime.now()
        print(f"[{BLUE}*{ESCAPE}] Monitoring ALL 802.11 probe requests...\n")
        sleep(TIME_WAIT)

        sniff(iface=interface, prn=probe_request_handler)

    elif args.presp:
        ST_TIME = datetime.now()
        print(f"[{BLUE}*{ESCAPE}] Monitoring ALL 802.11 probe responses...\n")
        sleep(TIME_WAIT)

        sniff(iface=interface, prn=probe_response_handler)
