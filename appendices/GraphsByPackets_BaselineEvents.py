#GraphsByPackets_BaselineEvents.py
from scapy.all import *
import plotly
from datetime import datetime
import pandas as pd
import pyshark
from pyshark.packet import consts
from pyshark.packet.common import Pickleable
import plotly.graph_objects as go
import sys
import numpy as np

#sys.argv[1] = Name of device
#sys.argv[2] = Choose between inbound, outbound or total packets
#sys.argv[3] = Type of event
#sys.argv[4] = Maximum value for y-axis

display=""

def graph_function():
    times=[]
    z=0
    for date in dates:
        if sys.argv[2] == "Total":
            file = r"C:\Users\Helene\Documents\IMT4905 - Erfaringsbasert master\Wireshark\Baseline\\"+sys.argv[1]+"\\"+sys.argv[3]+"\\"+sys.argv[1]+"_Baseline_"+sys.argv[3]+"_"+date+".pcapng"
            packets = pyshark.FileCapture(file)
        else:
            file = r"C:\Users\Helene\Documents\IMT4905 - Erfaringsbasert master\Wireshark\Baseline\\"+sys.argv[1]+"\\"+sys.argv[3]+"\\"+sys.argv[1]+"_Baseline_"+sys.argv[3]+"_"+date+".pcapng"
            packets = pyshark.FileCapture(file, display_filter=display)
        

        #Lists to hold packet info
        pktTimes=[]
        pkts=[]
        #Read each packet and append to the lists.
        for pkt in packets:
            n=1     
            pktTime=(pkt.sniff_time)
            pktTimes.append(pktTime)
            pkts.append(n)
            
        #This converts list to series
        packets = pd.Series(pkts).astype(int)
        
        #Convert the timestamp list to a pd date_time
        times = pd.to_datetime(pd.Series(pktTimes).astype(str),  errors='coerce')

        #Create the dataframe
        df  = pd.DataFrame({"Packets": packets, "Times": times})

        #set the date from a range to an timestamp
        df = df.set_index('Times')

        #Create a new dataframe of 2 second sums to pass to plotly
        df2=df.resample('2S').sum()

        #Create the graph
        GraphTitle=sys.argv[1]+"\n"+sys.argv[3]+"\n"+date
        fig = go.Figure({"data":[plotly.graph_objs.Scatter(x=df2.index, y=df2['Packets'])],"layout":plotly.graph_objs.Layout(title=GraphTitle,
                xaxis=dict(title="Time"),
                yaxis=dict(title=sys.argv[2]+" Packets"))})
            
        #Set the y-axis range
        fig.update_yaxes(range=[0,sys.argv[4]])
            
        #Set the x-axis range
        fig.update_layout(xaxis_range=[packetstart[z],packetend[z]])
                
        #Set the font
        fig.update_layout(title=GraphTitle, xaxis_title="Time", yaxis_title="Total Packets",font=dict(family="Times New Roman", size=26))
    
        #Display the graphs
        fig.show()
            
        z=z+1

if sys.argv[2] == "Outbound":
    if sys.argv[1] == "Netatmo":
        display = "wlan.sa == 70:EE:50:91:06:DE"
    elif sys.argv[1] == "Mill":
        display = "wlan.sa == B8:F0:09:B3:B3:78"
    elif sys.argv[1] == "Nedis":
        display = "wlan.sa == 2C:F4:32:29:36:DC"
        
elif sys.argv[2] == "Inbound":
    if sys.argv[1] == "Netatmo":
        display = "wlan.da == 70:EE:50:91:06:DE"
    elif sys.argv[1] == "Mill":
        display = "wlan.da == B8:F0:09:B3:B3:78"
    elif sys.argv[1] == "Nedis":
        display = "wlan.da == 2C:F4:32:29:36:DC"

if sys.argv[3] == "Shower":
        #Set the shower dates 
        dates = ["08.01","09.01","11.01","16.01","18.01","19.01","25.01","30.01","31.01","01.02"]
        
        #Set the x-axis range even tough packets are not sent
        packetstart=["2023-01-08 19:29","2023-01-09 19:29","2023-01-11 19:29","2023-01-16 19:29","2023-01-18 19:29","2023-01-19 19:29","2023-01-25 19:29","2023-01-30 19:29","2023-01-31 19:29","2023-02-01 19:29"]
        packetend=["2023-01-08 21:04","2023-01-09 21:04","2023-01-11 21:04","2023-01-16 21:04","2023-01-18 21:04","2023-01-19 21:04","2023-01-25 21:04","2023-01-30 21:04","2023-01-31 21:04","2023-02-01 21:04"]
            
        graph_function()

elif sys.argv[3] == "Cooking":
        #Set the cooking dates 
        dates = ["08.01","09.01","11.01","16.01","18.01","19.01","25.01","30.01","31.01","01.02"]
            
        #Set the x-axis range even tough packets are not sent
        packetstart=["2023-01-08 15:28","2023-01-09 15:28","2023-01-11 15:28","2023-01-16 15:28","2023-01-18 15:28","2023-01-19 15:28","2023-01-26 15:28","2023-01-30 15:28","2023-01-31 15:28","2023-02-01 15:28"]
        packetend=["2023-01-08 17:07","2023-01-09 17:07","2023-01-11 17:07","2023-01-16 17:07","2023-01-18 17:07","2023-01-19 17:07","2023-01-26 17:07","2023-01-30 17:07","2023-01-31 17:07","2023-02-01 17:07"]

        graph_function()
    
elif sys.argv[3] == "Window":
        #Set the window dates 
        dates = ["08.01-09.01","09.01-10.01","11.01-12.01","16.01-17.01","18.01-19.01","19.01-20.01","25.01-26.01","30.01-31.01","31.01-01.02","01.02-02-02"]
         
        #Set the x-axis range even tough packets are not sent
        packetstart=["2023-01-08 22:20","2023-01-09 22:20","2023-01-11 22:20","2023-01-16 22:20","2023-01-18 22:20","2023-01-19 22:20","2023-01-25 22:20","2023-01-30 22:20","2023-01-31 22:20","2023-02-01 22:20"]
        packetend=["2023-01-09 07:39","2023-01-10 07:39","2023-01-12 07:39","2023-01-17 07:39","2023-01-19 07:39","2023-01-20 07:39","2023-01-26 07:39","2023-01-31 07:39","2023-02-01 07:39","2023-02-02 07:39"]
            
        graph_function()