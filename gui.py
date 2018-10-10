import tkinter as tk
import sniffer as snf
import threading
import global_data
from datetime import datetime

listLength = 0

def newWindow():
    w = tk.Toplevel(root)
    return w

def fetchUpdate():
    try:
        selectionIndex = int(list1.curselection()[0])
    except IndexError:
        return
    detailsWindow = newWindow()
    detailsWindow.geometry('700x200')
    detailsWindow.title('Packet Details')
    if global_data.innerList and global_data.innerList[selectionIndex] != "NULL":
        version = global_data.innerList[selectionIndex].split('|')[0]
        headerLen = global_data.innerList[selectionIndex].split('|')[1]
        ttl = global_data.innerList[selectionIndex].split('|')[2]
        prtcl = global_data.innerList[selectionIndex].split('|')[3]
        sIP = global_data.innerList[selectionIndex].split('|')[4]
        dIP = global_data.innerList[selectionIndex].split('|')[5]

        versionLabel = tk.Label(detailsWindow,text = version,font='Helvetica 12 bold')
        versionLabel.grid(row = 0,column = 0,sticky = tk.W)
        hdrLabel = tk.Label(detailsWindow,text = headerLen,font='Helvetica 12 bold')
        hdrLabel.grid(row = 0,column = 1,sticky = tk.W)
        ttlLabel = tk.Label(detailsWindow,text = ttl,font='Helvetica 12 bold')
        ttlLabel.grid(row = 0,column = 2,sticky = tk.W)
        sipLabel = tk.Label(detailsWindow,text = sIP,font='Helvetica 12 bold')
        sipLabel.grid(row = 1,column = 1,sticky = tk.W)
        dipLabel = tk.Label(detailsWindow,text = dIP,font='Helvetica 12 bold')
        dipLabel.grid(row = 1,column = 2,sticky = tk.W)

        if global_data.protocolData and global_data.protocolData[selectionIndex] != "NULL":
            if global_data.protocolData[selectionIndex].split('|')[0] == "TCP":
                sPort = global_data.protocolData[selectionIndex].split('|')[1]
                dPort = global_data.protocolData[selectionIndex].split('|')[2]
                sNo = global_data.protocolData[selectionIndex].split('|')[3]
                aNo = global_data.protocolData[selectionIndex].split('|')[4]
                hlen = global_data.protocolData[selectionIndex].split('|')[5]
                Protocol = global_data.protocolData[selectionIndex].split('|')[0]

                spLabel = tk.Label(detailsWindow,text = sPort,font='Helvetica 12 bold')
                spLabel.grid(row = 2,column = 0,sticky = tk.W)
                dpLabel = tk.Label(detailsWindow,text = dPort,font='Helvetica 12 bold')
                dpLabel.grid(row = 2,column = 1,sticky = tk.W)
                seqLabel = tk.Label(detailsWindow,text = sNo,font='Helvetica 12 bold')
                seqLabel.grid(row = 3,column = 0,sticky = tk.W)
                ackLabel = tk.Label(detailsWindow,text = aNo,font='Helvetica 12 bold')
                ackLabel.grid(row = 3,column = 1,sticky = tk.W)
                hLabel = tk.Label(detailsWindow,text = hlen,font='Helvetica 12 bold')
                hLabel.grid(row = 4,column = 0,sticky = tk.W)
                protocolLabel = tk.Label(detailsWindow,text ='Protocol: '+ Protocol,font='Helvetica 12 bold')
                protocolLabel.grid(row = 1,column = 0,sticky = tk.W)

            elif global_data.protocolData[selectionIndex].split('|')[0] == "ICMP":
                typ = global_data.protocolData[selectionIndex].split('|')[1]
                code = global_data.protocolData[selectionIndex].split('|')[2]
                chksm = global_data.protocolData[selectionIndex].split('|')[3]
                Protocol = global_data.protocolData[selectionIndex].split('|')[0]

                typLabel = tk.Label(detailsWindow,text = typ,font='Helvetica 12 bold')
                typabel.grid(row = 2,column = 0,sticky = tk.W)
                codeLabel = tk.Label(detailsWindow,text = code,font='Helvetica 12 bold')
                codeLabel.grid(row = 2,column = 1,sticky = tk.W)
                chksmLabel = tk.Label(detailsWindow,text = chksm,font='Helvetica 12 bold')
                chksmLabel.grid(row = 2,column = 2,sticky = tk.W)
                protocolLabel = tk.Label(detailsWindow,text ='Protocol: '+ Protocol,font='Helvetica 12 bold')
                protocolLabel.grid(row = 1,column = 0,sticky = tk.W)

            elif global_data.protocolData[selectionIndex].split('|')[0] == "UDP":
                sPort = global_data.protocolData[selectionIndex].split('|')[1]
                dPort = global_data.protocolData[selectionIndex].split('|')[2]
                length = global_data.protocolData[selectionIndex].split('|')[3]
                chksum = global_data.protocolData[selectionIndex].split('|')[4]
                Protocol = global_data.protocolData[selectionIndex].split('|')[0]

                spLabel = tk.Label(detailsWindow,text = sPort,font='Helvetica 12 bold')
                spLabel.grid(row = 2,column = 0,sticky = tk.W)
                dpLabel = tk.Label(detailsWindow,text = dPort,font='Helvetica 12 bold')
                dpLabel.grid(row = 2,column = 1,sticky = tk.W)
                lenLabel = tk.Label(detailsWindow,text = length,font='Helvetica 12 bold')
                lenLabel.grid(row = 3,column = 0,sticky = tk.W)
                chksumLabel = tk.Label(detailsWindow,text = chksum,font='Helvetica 12 bold')
                chksumLabel.grid(row = 3,column = 1,sticky = tk.W)
                protocolLabel = tk.Label(detailsWindow,text = 'Protocol: '+Protocol,font='Helvetica 12 bold')
                protocolLabel.grid(row = 1,column = 0,sticky = tk.W)

            else:
                errLabel = tk.Label(detailsWindow,text = "Protocol other than tcp/udp/icmp",fg = 'red',font='Helvetica 10 bold')
                errLabel.grid(row=2,column=0)


    else:
        errorLabel = tk.Label(detailsWindow,text = 'Uh oh !!.....It looks like this is an unsupported packet type.',fg = 'red',font='Helvetica 12 bold')
        errorLabel.pack()

def start():
    def initiate():
        global_data.init = True
        snf.sniffer()
    thread = threading.Thread(target=initiate)  
    thread.start()  

def stop(): 
    global_data.init = False
    print("Execution Stoped.")

def kill():
    stop()
    root.destroy()

def tick():
    time_string = datetime.now().time()
    current_status = global_data.init
    if current_status == True:
        status.configure(text="Status: ONLINE",font='Helvetica 10 bold')
    else:
        status.configure(text="Status: OFFLINE",font='Helvetica 10 bold')
    clock.config(text="Time: "+str(time_string)[:8])
    clock.after(200, tick)

def listUpdate():
    global listLength
    if listLength != len(global_data.topList):
        for i in range(listLength,len(global_data.topList)):
            list1.insert(tk.END,global_data.topList[i])
            packets.configure(text="Packets Captured: "+str(i+1))
    listLength = len(global_data.topList)
    list1.after(500, listUpdate)


root = tk.Tk()
root.geometry("750x650")
root.title("Network Packet Sniffer")
root.configure(background = 'white smoke')


#Frames
frame1 = tk.Frame(root)
frame1.grid(row=0,column=1,pady = (20,10))
frame2 = tk.Frame(root)
frame2.grid(row=1,column=0,sticky = tk.S)
frame3 = tk.Frame(root)
frame3.grid(row = 1, column = 1)
frame4 = tk.Frame(root)
frame4.grid(row=2,column=0,padx = (10,10))
frame5 = tk.Frame(root,background = 'white smoke')
frame5.grid(row = 0,column = 0,sticky = tk.W,padx = (15,5),pady = (10,5))

#Buttons
start_btn = tk.Button(frame1,text = "Start" ,command = start,bg = 'green2',activebackground = 'green',font='Helvetica 10 bold')
start_btn.pack(side = 'left')
stop_btn = tk.Button(frame1,text = "Stop" ,command = stop,bg = 'red',activebackground = 'red2',font='Helvetica 10 bold')
stop_btn.pack(side = 'left')
exit_btn = tk.Button(frame1,text = "Exit" ,command = kill,bg = 'yellow',activebackground = 'yellow2',font='Helvetica 10 bold')
exit_btn.pack(side = 'left')
detail = tk.Button(root,command = fetchUpdate,text = "View Details")
detail.grid(row = 2,column = 1)

#Scrollbar
scrollbar = tk.Scrollbar(frame4, orient=tk.VERTICAL)

#List
list1 = tk.Listbox(frame4, height = "31",width = "65",bd = "4",background = 'ghost white',yscrollcommand=scrollbar.set)
scrollbar.config(command=list1.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
list1.pack(side=tk.LEFT)

#Labels
date = tk.Label(frame2,text = "Date: "+str(datetime.now().date()))
date.pack(side = tk.LEFT,padx = (10,20))
clock = tk.Label(frame2)
clock.pack(side = tk.LEFT) 
status = tk.Label(frame3)
status.pack(side = tk.TOP)
packets = tk.Label(frame3,text="Packets Captured: NONE")
packets.pack(side = tk.BOTTOM)
img = tk.PhotoImage(file = 'rsz_41logo.png')
logo = tk.Label(frame5,image = img,background = 'white smoke')
logo.pack(side = tk.LEFT)
title = tk.Label(frame5,text='Sniffy-Py',font='Helvetica 15 bold',background = 'white smoke')
title.pack(side = tk.RIGHT)

tick()
listUpdate()
root.mainloop()