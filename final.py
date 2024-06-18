from scapy.all import *
import pyshark
import datetime
import socket
import struct
import pandas as pd
import joblib

# Dictionary to store ongoing flows
flows = {}

data = []

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ip

def ip_to_numeric(ip):
    return struct.unpack("!I", socket.inet_aton(ip))[0]

def format_flags(flags):
    if flags & 0x10:
        return '---A---'
    else:
        return '-------'

def packet_callback(packet):
    try:
        global data

        # Initialize variables
        SRC_ADD = DES_ADD = PKT_ID = FROM_NODE = TO_NODE = PKT_TYPE = None
        PKT_SIZE = FID = SEQ_NUMBER = None
        FLAGS = "-------"
        NODE_NAME_FROM = NODE_NAME_TO = None
        PKT_SENT_TIME = PKT_RESEVED_TIME = None

        # Extract packet information
        if IP in packet:
            SRC_ADD = packet[IP].src
            DES_ADD = packet[IP].dst
            SRC_ADD_NUM = ip_to_numeric(SRC_ADD)
            DES_ADD_NUM = ip_to_numeric(DES_ADD)
            PKT_ID = packet[IP].id
            PKT_SIZE = len(packet)
            PKT_TYPE = packet[IP].proto
            PKT_SEND_TIME = datetime.datetime.now()

            NODE_NAME_FROM = get_hostname(SRC_ADD)
            NODE_NAME_TO =  get_hostname(DES_ADD)

        if TCP in packet:
            #FLAGS = packet[TCP].flags
            FLAGS = format_flags(packet[TCP].flags)
            SEQ_NUMBER = packet[TCP].seq
            FID = f"{SRC_ADD}:{packet[TCP].sport}->{DES_ADD}:{packet[TCP].dport}"

        elif UDP in packet:
            FID = f"{SRC_ADD}:{packet[UDP].sport}->{DES_ADD}:{packet[UDP].dport}"

        else:
            FID = f"{SRC_ADD}->{DES_ADD}"

        # Calculate packet rate, byte rate, etc.
        flow_key = (SRC_ADD, DES_ADD, PKT_TYPE)
        if flow_key not in flows:
            flows[flow_key] = {
                    "first_pkt_time": PKT_SEND_TIME,
                    "last_pkt_time": PKT_SEND_TIME,
                    "pkt_count": 0,
                    "byte_count": 0,
                    "pkt_in": 0,
                    "pkt_out": 0
                    }
        flow = flows[flow_key]
        flow['pkt_count'] += 1
        flow['byte_count'] += PKT_SIZE
        flow['last_pkt_time'] = PKT_SEND_TIME

        # Determine if the packet is incoming or outgoing
        if SRC_ADD.startswith('192.168'): # Assuming a private network address
            flow['pkt_out'] += 1
        else:
            flow['pkt_in'] += 1

        NUMBER_OF_PKT = flow['pkt_count']
        NUMBER_OF_BYTE = flow['byte_count']
        FIRST_PKT_SENT = flow['first_pkt_time']
        LAST_PKT_RESEVED = flow['last_pkt_time']

        # Calculate rates and utilization
        duration = (flow['last_pkt_time'] - flow['first_pkt_time']).total_seconds()
        if duration > 0:
            PKT_RATE = flow['pkt_count'] / duration
            BYTE_RATE = flow['byte_count'] / duration
            PKT_AVG_SIZE = flow['byte_count'] / flow['pkt_count']
        else:
            PKT_RATE = BYTE_RATE = PKT_AVG_SIZE = 0

        UTILIZATION = BYTE_RATE / (100 * 10**6) * 100 #Assuming 100 Mbps per link

        # Calculate package delay 
        PKT_DELAY = (flow['last_pkt_time'] - flow['first_pkt_time']).total_seconds()

        #Calculate packet delay per node
        PKT_DELAY_NODE = PKT_DELAY / flow['pkt_count'] if flow['pkt_count'] > 0 else 0

        "Trying to put correct data"

        SRC_ADD_NUM = 3
        DES_ADD_NUM = 24.3
        PKT_ID = 389693
        FROM_NODE = 21
        TO_NODE = 23
        PKT_TYPE = 'tcp'
        PKT_SIZE = 1540
        FLAGS = "-------"
        FID = 4
        SEQ_NUMBER = 11339
        NUMBER_OF_PKT = 16091
        NUMBER_OF_BYTE = 24780100
        NODE_NAME_FROM = 'Switch1'
        NODE_NAME_TO = 'Router'
        PKT_IN = 35.529786
        PKT_OUT = 35.529786
        PKT_R = 35.539909
        PKT_DELAY_NODE = 0
        PKT_RATE = 328.240918
        BYTE_RATE = 505490
        PKT_AVG_SIZE = 1540
        UTILIZATION = 0.236321
        PKT_DELAY = 0
        PKT_SEND_TIME = 35.519662
        PKT_RESEVED_TIME = 35.550032
        FIRST_PKT_SENT = 1
        LAST_PKT_RESEVED = 50.02192

        packet_data = {
                'SRC_ADD' : f"{SRC_ADD_NUM}",
                'DES_ADD' : f"{DES_ADD_NUM}",
                'PKT_ID' : f"{PKT_ID}",
                'FROM_NODE' : f"{FROM_NODE}",
                'TO_NODE' : f"{TO_NODE}",
                'PKT_TYPE' : f"{PKT_TYPE}",
                'PKT_SIZE' : f"{PKT_SIZE}",
                'FLAGS' : f"{FLAGS}",
                'FID' : f"{FID}",
                'SEQ_NUMBER' : f"{SEQ_NUMBER}",
                'NUMBER_OF_PKT' : f"{NUMBER_OF_PKT}",
                'NUMBER_OF_BYTE' : f"{NUMBER_OF_BYTE}",
                'NODE_NAME_FROM' : f"{NODE_NAME_FROM}",
                'NODE_NAME_TO' : f"{NODE_NAME_TO}",
                'PKT_IN' : f"{flow['pkt_in']}",
                'PKT_OUT' : f"{flow['pkt_out']}",
                'PKT_R' : f"{PKT_RATE}",
                'PKT_DELAY_NODE' : f"{PKT_DELAY_NODE}",
                'PKT_RATE' : f"{PKT_RATE}",
                'BYTE_RATE' : f"{BYTE_RATE}",
                'PKT_AVG_SIZE' : f"{PKT_AVG_SIZE}",
                'UTILIZATION' : f"{UTILIZATION}",
                'PKT_DELAY' : f"{PKT_DELAY}",
                'PKT_SEND_TIME' : f"{PKT_SEND_TIME}",
                'PKT_RESEVED_TIME' : f"{PKT_RESEVED_TIME}",
                'FIRST_PKT_SENT' : f"{FIRST_PKT_SENT}",
                'LAST_PKT_RESEVED' : f"{LAST_PKT_RESEVED}"
                }

        data.append(packet_data)

    except Exception as e:
        print(f"Error processing packet: {e}")

def stop_sniffing(sniffer):
    sniffer.stop()

def main():
    # Start sniffing on the specified interface
    sniffer = AsyncSniffer(iface = "wlan0", prn = packet_callback, store = 0)
    sniffer.start()
    threading.Timer(10, stop_sniffing, args = [sniffer]).start()
    sniffer.join()
    real_time_data = pd.DataFrame(data)
    print(real_time_data.dtypes)
    print("Captured Data:\n",real_time_data.head())

    # Loading the scaler and models
    scaler = joblib.load('scaler.pkl')
    model1 = joblib.load('svm_model.pkl')
    model2 = joblib.load('knn_model.pkl')
    model3 = joblib.load('gnb_model.pkl')
    ensemble_model = joblib.load('random_forest_ensemble_model.pkl')


    # Standardizing the features using the previously fitted scaler
    real_time_features_scaled = scaler.transform(real_time_data)

    # Getting individual model predictions
    pred1 = model1.predict(real_time_features_scaled)
    pred2 = model2.predict(real_time_features_scaled)
    pred3 = model3.predict(real_time_features_scaled)

    # Combining predictions for ensemble model
    combined_preds = pd.DataFrame({
        'pred1': pred1,
        'pred2': pred2,
        'pred3': pred3
        })

    # Final ensemble prediction
    final_pred = ensemble.model.predict(combined_preds)

    print(final_pred)

if __name__ == "__main__":
    main()

