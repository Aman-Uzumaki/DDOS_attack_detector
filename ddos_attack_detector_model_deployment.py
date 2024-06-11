from scapy.all import *
import datetime
import socket
import pandas as pd
import joblib
import threading
import ipaddress
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier  # Importing the ensemble model

# Define the ensemble model
ensemble_model = RandomForestClassifier()  # You can customize this based on your requirements

# Dictionary to store ongoing flows
flows = {}
data = []

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ip

def ip_to_numeric(ip):
    return int(ipaddress.IPv4Address(ip))

def packet_callback(packet):
    try:
        global data

        # Initialize variables
        SRC_ADD = DES_ADD = PKT_ID = FROM_NODE = TO_NODE = PKT_TYPE = None
        PKT_SIZE = FLAGS = FID = SEQ_NUMBER = None
        NODE_NAME_FROM = NODE_NAME_TO = None
        PKT_SEND_TIME = PKT_RESEVED_TIME = None

        # Extract packet information
        if IP in packet:
            SRC_ADD = ip_to_numeric(packet[IP].src)
            DES_ADD = ip_to_numeric(packet[IP].dst)
            PKT_ID = packet[IP].id
            PKT_SIZE = len(packet)
            PKT_SEND_TIME = datetime.datetime.now().timestamp()

            NODE_NAME_FROM = get_hostname(packet[IP].src)
            NODE_NAME_TO = get_hostname(packet[IP].dst)

            # Assuming FROM_NODE and TO_NODE need to be derived from node names
            FROM_NODE = hash(NODE_NAME_FROM) % 1000
            TO_NODE = hash(NODE_NAME_TO) % 1000

            proto_map = {6: 'tcp', 17: 'udp', 1: 'icmp'}
            PKT_TYPE = proto_map.get(packet[IP].proto, 'unknown')

        if TCP in packet:
            FLAGS = packet[TCP].flags
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
        if packet[IP].src.startswith('192.168'): # Assuming a private network address
            flow['pkt_out'] += 1
        else:
            flow['pkt_in'] += 1

        NUMBER_OF_PKT = flow['pkt_count']
        NUMBER_OF_BYTE = flow['byte_count']
        FIRST_PKT_SENT = flow['first_pkt_time']
        LAST_PKT_RESEVED = flow['last_pkt_time']

        # Calculate rates and utilization
        duration = (flow['last_pkt_time'] - flow['first_pkt_time'])
        if duration > 0:
            PKT_RATE = flow['pkt_count'] / duration
            BYTE_RATE = flow['byte_count'] / duration
            PKT_AVG_SIZE = flow['byte_count'] / flow['pkt_count']
        else:
            PKT_RATE = BYTE_RATE = PKT_AVG_SIZE = 0

        UTILIZATION = BYTE_RATE / (100 * 10**6) * 100 #Assuming 100 Mbps per link

        # Calculate package delay 
        PKT_DELAY = (flow['last_pkt_time'] - flow['first_pkt_time'])

        # Calculate packet delay per node
        PKT_DELAY_NODE = PKT_DELAY / flow['pkt_count'] if flow['pkt_count'] > 0 else 0

        packet_data = {
                'SRC_ADD' : SRC_ADD,
                'DES_ADD' : DES_ADD,
                'PKT_ID' : PKT_ID,
                'FROM_NODE' : FROM_NODE,
                'TO_NODE' : TO_NODE,
                'PKT_TYPE' : PKT_TYPE,
                'FLAGS' : FLAGS,
                'FID' : FID,
                'SEQ_NUMBER' : SEQ_NUMBER,
                'NUMBER_OF_PKT' : NUMBER_OF_PKT,
                'NUMBER_OF_BYTE' : NUMBER_OF_BYTE,
                'NODE_NAME_FROM' : NODE_NAME_FROM,
                'NODE_NAME_TO' : NODE_NAME_TO,
                'PKT_IN' : flow['pkt_in'],
                'PKT_OUT' : flow['pkt_out'],
                'PKT_R' : PKT_RATE,
                'PKT_DELAY_NODE' : PKT_DELAY_NODE,
                'PKT_RATE' : PKT_RATE,
                'BYTE_RATE' : BYTE_RATE,
                'PKT_AVG_SIZE' : PKT_AVG_SIZE,
                'UTILIZATION' : UTILIZATION,
                'PKT_DELAY' : PKT_DELAY,
                'PKT_SEND_TIME' : PKT_SEND_TIME,
                'PKT_RESEVED_TIME' : PKT_RESEVED_TIME,
                'FIRST_PKT_SENT' : FIRST_PKT_SENT,
                'LAST_PKT_RESEVED' : LAST_PKT_RESEVED
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
    
    if len(data) == 0:
        print("No data captured.")
        return

    real_time_data = pd.DataFrame(data)
    print("Captured Data:\n", real_time_data.head())

    # Define column transformer
    categorical_columns = ['PKT_TYPE', 'FLAGS', 'NODE_NAME_FROM', 'NODE_NAME_TO']
    numeric_columns = real_time_data.columns.difference(categorical_columns)
    preprocessor = ColumnTransformer(
        transformers=[
            ('num', StandardScaler(), numeric_columns),
            ('cat', OneHotEncoder(), categorical_columns)
        ])

    # Create a pipeline with preprocessing and modeling steps
    pipeline = Pipeline(steps=[('preprocessor', preprocessor),
                               ('model', ensemble_model)])

    # Fit the pipeline
    target_variable = 'target'  # Replace 'target' with your target variable column name
    pipeline.fit(real_time_data, real_time_data[target_variable])

    # Make predictions
    predictions = pipeline.predict(real_time_data)
    print("Predictions:",predictions)

if __name__ == "__main__":
    main()
