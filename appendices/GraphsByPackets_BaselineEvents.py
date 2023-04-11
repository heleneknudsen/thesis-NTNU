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
            file = r"C:\Users\Helene\Documents\IMT4905 - Erfaringsbasert master\Fra wireshark\Baseline\\"+sys.argv[3]+"\\"+sys.argv[1]+"\\"+sys.argv[1]+"_Baseline_"+sys.argv[3]+"_"+date+".pcapng"
            packets = pyshark.FileCapture(file)
        else:
            file = r"C:\Users\Helene\Documents\IMT4905 - Erfaringsbasert master\Fra wireshark\Baseline\\"+sys.argv[3]+"\\"+sys.argv[1]+"\\"+sys.argv[1]+"_Baseline_"+sys.argv[3]+"_"+date+".pcapng"
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
    
            #Mark the event time
            fig.add_vrect(x0=eventstart[z], x1=eventstop[z], fillcolor="salmon", opacity=0.5, layer="below", line_width=0),
            
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
        dates = ["06.03","07.03","08.03","09.03","10.03","11.03","12.03","13.03","14.03","15.03"]
            
        #Set the x-axis range even tough packets are not sent
        packetstart=["2023-03-06 19:32","2023-03-07 19:32","2023-03-08 19:32","2023-03-09 19:32","2023-03-10 19:32","2023-03-11 19:32","2023-03-12 19:32","2023-03-13 19:32","2023-03-14 19:32","2023-03-15 19:32"]
        packetend=["2023-03-06 20:50","2023-03-07 20:50","2023-03-08 20:50","2023-03-09 20:50","2023-03-10 20:50","2023-03-11 20:50","2023-03-12 20:50","2023-03-13 20:50","2023-03-14 20:50","2023-03-15 20:50"]
            
        #Add color to when the event occured
        eventstart=["2023-03-06 20:02","2023-03-07 20:02","2023-03-08 20:02","2023-03-09 20:02","2023-03-10 20:02","2023-03-11 20:02","2023-03-12 20:02","2023-03-13 20:02","2023-03-14 20:02","2023-03-15 20:02"]
        eventstop=["2023-03-06 20:20","2023-03-07 20:20","2023-03-08 20:20","2023-03-09 20:20","2023-03-10 20:20","2023-03-11 20:20","2023-03-12 20:20","2023-03-13 20:20","2023-03-14 20:20","2023-03-15 20:20"]
        
        graph_function()

    elif sys.argv[3] == "Cooking":
        #Set the cooking dates 
        dates = ["06.03","07.03","08.03","09.03","10.03","11.03","12.03","13.03","14.03","15.03"]
            
        #Set the x-axis range even tough packets are not sent
        packetstart=["2023-03-06 15:32","2023-03-07 15:32","2023-03-08 15:32","2023-03-09 15:32","2023-03-10 15:32","2023-03-11 15:32","2023-03-12 15:32","2023-03-13 15:32","2023-03-14 15:32","2023-03-15 15:32"]
        packetend=["2023-03-06 16:51","2023-03-07 16:51","2023-03-08 16:51","2023-03-09 16:51","2023-03-10 16:51","2023-03-11 16:51","2023-03-12 16:51","2023-03-13 16:51","2023-03-14 16:51","2023-03-15 16:51"]
            
        #Add color to when the event occured
        eventstart=["2023-03-06 16:02","2023-03-07 16:02","2023-03-08 16:02","2023-03-09 16:02","2023-03-10 16:02","2023-03-11 16:02","2023-03-12 16:02","2023-03-13 16:02","2023-03-14 16:02","2023-03-15 16:02"]
        eventstop=["2023-03-06 16:21","2023-03-07 16:21","2023-03-08 16:21","2023-03-09 16:21","2023-03-10 16:21","2023-03-11 16:21","2023-03-12 16:21","2023-03-13 16:21","2023-03-14 16:21","2023-03-15 16:21"]
        
        graph_function()
    
    elif sys.argv[3] == "Window":
        #Set the window dates 
        dates = ["06.03-07.03","07.03-08.03","08.03-09.03","09.03-10.03","10.03-11.03","11.03-12.03","12.03-13.03","13.03-14.03","14.03-15.03"]
         
        #Set the x-axis range even tough packets are not sent
        packetstart=["2023-03-06 22:31","2023-03-07 22:31","2023-03-08 22:31","2023-03-09 22:31","2023-03-10 22:31","2023-03-11 22:31","2023-03-12 22:31","2023-03-13 22:31","2023-03-14 22:31"]
        packetend=["2023-03-07 07:29","2023-03-08 07:29","2023-03-09 07:29","2023-03-10 07:29","2023-03-11 07:29","2023-03-12 07:29","2023-03-13 07:29","2023-03-14 07:29","2023-03-15 07:29"]
            
        #Add color to when the event occured
        eventstart=["2023-03-06 23:01","2023-03-07 23:01","2023-03-08 23:01","2023-03-09 23:01","2023-03-10 23:01","2023-03-11 23:01","2023-03-12 23:01","2023-03-13 23:01","2023-03-14 23:01"]
        eventstop=["2023-03-07 06:59","2023-03-08 06:59","2023-03-09 06:59","2023-03-10 06:59","2023-03-11 06:59","2023-03-12 06:59","2023-03-13 06:59","2023-03-14 06:59","2023-03-15 06:59"]

        graph_function()