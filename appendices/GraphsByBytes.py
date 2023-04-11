#GraphsByBytes.py
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
    bytes=[]
    z=0
    for date in dates:
        if sys.argv[2] == "Total":
            file = r"C:\Users\Helene\Documents\IMT4905 - Erfaringsbasert master\Fra wireshark\\"+sys.argv[3]+"\\"+sys.argv[1]+"\\"+sys.argv[1]+"_"+sys.argv[3]+"_"+date+".pcapng"
            packets = pyshark.FileCapture(file)
        else:
            file = r"C:\Users\Helene\Documents\IMT4905 - Erfaringsbasert master\Fra wireshark\\"+sys.argv[3]+"\\"+sys.argv[1]+"\\"+sys.argv[1]+"_"+sys.argv[3]+"_"+date+".pcapng"
            packets = pyshark.FileCapture(file, display_filter=display)
        

        # #Lists to hold packet info
        pktTimes=[]
        pktBytes=[]
        #Read each packet and append to the lists.
        for pkt in packets:   
            pktTime=(pkt.sniff_time)
            pktByte=(pkt.length)
    
            pktBytes.append(pktByte)
            pktTimes.append(pktTime)
  
        #This converts list to series
        bytes = pd.Series(pktBytes).astype(int)
            
        #Convert the timestamp list to a pd date_time
        times = pd.to_datetime(pd.Series(pktTimes).astype(str),  errors='coerce')

        #Create the dataframe
        df  = pd.DataFrame({"Bytes": bytes, "Times":times})

        #set the date from a range to an timestamp
        df = df.set_index('Times')

        #Create a new dataframe of 2 second sums to pass to plotly
        df2=df.resample('2S').sum()

        #Create the graph
        GraphTitle=sys.argv[1]+"\n"+sys.argv[3]+"\n"
        fig = go.Figure({"data":[plotly.graph_objs.Scatter(x=df2.index, y=df2['Bytes'])],"layout":plotly.graph_objs.Layout(title=GraphTitle,
                xaxis=dict(title="Time"),
                yaxis=dict(title=sys.argv[2]+" Bytes"))})
            
        #Set the y-axis range
        fig.update_yaxes(range=[0,sys.argv[4]])
        
        #Set the font
        fig.update_layout(title=GraphTitle, xaxis_title="Time", yaxis_title= sys.argv[2]+" Bytes",font=dict(family="Times New Roman", size=26))
            
        #Set the x-axis range
        fig.update_layout(xaxis_range=[packetstart[z],packetend[z]])
            
        if sys.argv[3] == "Weekend" or sys.argv[3] == "Baseline":
                pass              
        else:
            #Mark the event time
            fig.add_vrect(x0=eventstart[z], x1=eventstop[z], fillcolor="salmon", opacity=0.5, layer="below", line_width=0),
            
        #Display the graphs
        fig.show()
            
        z=z+1

if sys.argv[2] == "Outbound":
    #Set display-filter to MAC-address
    if sys.argv[1] == "Netatmo":
        display = "wlan.sa == 70:EE:50:91:06:DE"
    elif sys.argv[1] == "Mill":
        display = "wlan.sa == B8:F0:09:B3:B3:78"
    elif sys.argv[1] == "Nedis":
        display = "wlan.sa == 2C:F4:32:29:36:DC"
        
elif sys.argv[2] == "Inbound":
    #Set display-filter to MAC-address
    if sys.argv[1] == "Netatmo":
        display = "wlan.da == 70:EE:50:91:06:DE"
    elif sys.argv[1] == "Mill":
        display = "wlan.da == B8:F0:09:B3:B3:78"
    elif sys.argv[1] == "Nedis":
        display = "wlan.da == 2C:F4:32:29:36:DC"
else:
    pass

    if sys.argv[3] == "Shower":
        #Set the shower dates 
        dates = ["08.01","09.01","11.01","12.01","16.01","18.01","19.01","23.01","25.01","26.01","30.01","31.01","01.02","02.02","06.02"]
            
        #Set the x-axis range even tough packets are not sent
        packetstart=["2023-01-08 19:29","2023-01-09 19:44","2023-01-11 19:31","2023-01-12 19:29","2023-01-16 19:42","2023-01-18 19:32","2023-01-19 19:30","2023-01-23 19:30","2023-01-25 19:33","2023-01-26 19:33","2023-01-30 19:30","2023-01-31 19:31","2023-02-01 19:30","2023-02-02 19:30","2023-02-06 19:30"]
        packetend=["2023-01-08 20:44","2023-01-09 21:04","2023-01-11 20:47","2023-01-12 20:51","2023-01-16 21:01","2023-01-18 20:49","2023-01-19 20:46","2023-01-23 20:51","2023-01-25 20:49","2023-01-26 20:49","2023-01-30 20:48","2023-01-31 20:47","2023-02-01 20:46","2023-02-02 20:47","2023-02-06 20:48"]
            
        #Add color to when the event occured
        eventstart=["2023-01-08 19:59","2023-01-09 20:14","2023-01-11 20:01","2023-01-12 19:59","2023-01-16 20:12","2023-01-18 20:02","2023-01-19 20:00","2023-01-23 20:00","2023-01-25 20:03","2023-01-26 20:03","2023-01-30 20:00","2023-01-31 20:01","2023-02-01 20:00","2023-02-02 20:00","2023-02-06 20:00"]
        eventstop=["2023-01-08 20:14","2023-01-09 20:34","2023-01-11 20:17","2023-01-12 20:21","2023-01-16 20:31","2023-01-18 20:19","2023-01-19 20:16","2023-01-23 20:21","2023-01-25 20:19","2023-01-26 20:19","2023-01-30 20:18","2023-01-31 20:17","2023-02-01 20:16","2023-02-02 20:17","2023-02-06 20:18"]
        
        graph_function()

    elif sys.argv[3] == "Cooking":
        #Set the cooking dates 
        dates = ["08.01","09.01","10.01","11.01","12.01","16.01","18.01","19.01","24.01","25.01","26.01","30.01","31.01","01.02","02.02"]
            
        #Set the x-axis range even tough packets are not sent
        packetstart=["2023-01-08 15:28","2023-01-09 15:29","2023-01-10 15:31","2023-01-11 15:35","2023-01-12 15:40","2023-01-16 15:32","2023-01-18 15:34","2023-01-19 15:31","2023-01-24 15:27","2023-01-25 15:32","2023-01-26 15:31","2023-01-30 15:31","2023-01-31 15:31","2023-02-01 15:32","2023-02-02 15:32"]
        packetend=["2023-01-08 16:52","2023-01-09 16:51","2023-01-10 16:57","2023-01-11 17:07","2023-01-12 16:58","2023-01-16 16:55","2023-01-18 16:55","2023-01-19 16:48","2023-01-24 16:50","2023-01-25 16:43","2023-01-26 16:55","2023-01-30 16:49","2023-01-31 16:51","2023-02-01 16:52","2023-02-02 16:52"]
            
        #Add color to when the event occured
        eventstart=["2023-01-08 15:58","2023-01-09 15:59","2023-01-10 16:01","2023-01-11 16:05","2023-01-12 16:10","2023-01-16 16:02","2023-01-18 16:04","2023-01-19 16:01","2023-01-24 15:57","2023-01-25 16:02","2023-01-26 16:01","2023-01-30 16:01","2023-01-31 16:01","2023-02-01 16:02","2023-02-02 16:02"]
        eventstop=["2023-01-08 16:22","2023-01-09 16:21","2023-01-10 16:27","2023-01-11 16:37","2023-01-12 16:28","2023-01-16 16:25","2023-01-18 16:25","2023-01-19 16:18","2023-01-24 16:20","2023-01-25 16:13","2023-01-26 16:25","2023-01-30 16:19","2023-01-31 16:21","2023-02-01 16:22","2023-02-02 16:22"]
        
        graph_function()
    
    elif sys.argv[3] == "Window":
        #Set the window dates 
        dates = ["08.01-09.01","09.01-10.01","10.01-11.01","11.01-12.01","12.01-13.01","16.01-17.01","18.01-19.01","19.01-20.01","23.01-24.01","24.01-25.01","25.01-26.01","30.01-31.01","31.01-01.02","01.02-02.02","02.02-03.02"]
         
        #Set the x-axis range even tough packets are not sent
        packetstart=["2023-01-08 22:30","2023-01-09 22:30","2023-01-10 22:30","2023-01-11 22:20","2023-01-12 22:30","2023-01-16 22:40","2023-01-18 22:45","2023-01-19 22:32","2023-01-23 22:29","2023-01-24 22:29","2023-01-25 22:29","2023-01-30 22:30","2023-01-31 22:29","2023-02-01 22:29","2023-02-02 22:29"]
        packetend=["2023-01-09 07:30","2023-01-10 07:30","2023-01-11 07:30","2023-01-12 07:30","2023-01-13 07:30","2023-01-17 07:26","2023-01-19 07:39","2023-01-20 07:29","2023-01-24 07:25","2023-01-25 07:25","2023-01-26 07:25","2023-01-31 07:26","2023-02-01 07:30","2023-02-02 07:29","2023-02-03 07:29"]
            
        #Add color to when the event occured
        eventstart=["2023-01-08 23:00","2023-01-09 23:00","2023-01-10 23:00","2023-01-11 22:50","2023-01-12 23:00","2023-01-16 23:10","2023-01-18 23:15","2023-01-19 23:02","2023-01-23 22:59","2023-01-24 22:59","2023-01-25 22:59","2023-01-30 23:00","2023-01-31 22:59","2023-02-01 22:59","2023-02-02 22:59"]
        eventstop=["2023-01-09 07:00","2023-01-10 07:00","2023-01-11 07:00","2023-01-12 07:00","2023-01-13 07:00","2023-01-17 06:56","2023-01-19 07:09","2023-01-20 06:59","2023-01-24 06:55","2023-01-25 06:55","2023-01-26 06:55","2023-01-31 06:56","2023-02-01 07:00","2023-02-02 06:59","2023-02-03 06:59"]

        graph_function()

    elif sys.argv[3] == "Weekend":
        #Set the weekend dates 
        dates = ["23.12-25.12","30.12-01.01","13.01-15.01","20.01-22.01","27.01-29.01","03.02-05.02","10.02-12.02","17.02-19.02","24.02-26.02","03.03-05.03","10.03-12.03","17.03-19.03","24.03-26.03","28.03-30.03","31.03-02.04"]
        
        #Set the x-axis range even tough packets are not sent
        packetstart=["2022-12-23 16:00","2022-12-30 16:00","2023-01-13 16:00","2023-01-20 16:00","2023-01-27 16:00","2023-02-03 16:00","2023-02-10 16:00","2023-02-17 16:00","2023-02-24 16:00","2023-03-03 16:00","2023-03-10 16:00","2023-03-17 16:00","2023-03-24 16:00","2023-03-28 16:00","2023-03-31 16:00"]
        packetend=["2022-12-25 22:00","2023-01-01 22:00","2023-01-15 22:00","2023-01-22 22:00","2023-01-29 22:00","2023-02-05 22:00","2023-02-12 22:00","2023-02-19 22:00","2023-02-26 22:00","2023-03-05 22:00","2023-03-12 22:00","2023-03-19 22:00","2023-03-26 22:00","2023-03-30 22:00","2023-04-02 22:00"]
        
        graph_function()

    elif sys.argv[3] == "Baseline":
        #Set the baseline dates 
        dates = ["06.03-15.03"]
        
        #Set the x-axis range even tough packets are not sent
        packetstart=["2023-03-06 00:00"]
        packetend=["2023-03-15 23:59"]
        
        graph_function()