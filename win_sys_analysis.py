import win32evtlog, wmi, datetime, json
from collections import defaultdict
from pathlib import Path

class WindowsSystemAnalyzer:
    def __init__(self):
        self.wmi_connection = wmi.WMI()
        self.system_info = {}
        
    def collect_hardware_info(self):
        #Collect hardware information using WMI.
        
        # CPU Information
        self.system_info['cpu'] = [{
            'name': cpu.Name,
            'cores': cpu.NumberOfCores,
            'threads': cpu.NumberOfLogicalProcessors,
            'max_clock': cpu.MaxClockSpeed
        } for cpu in self.wmi_connection.Win32_Processor()]

        # Memory Information
        self.system_info['memory'] = [{
            'capacity_gb': round(int(mem.Capacity) / (1024**3), 2),
            'speed': mem.Speed,
            'manufacturer': mem.Manufacturer
        } for mem in self.wmi_connection.Win32_PhysicalMemory()]

        # Disk Drives
        self.system_info['disks'] = [{
            'name': disk.Caption,
            'size_gb': round(int(disk.Size) / (1024**3), 2),
            'interface': disk.InterfaceType,
            'model': disk.Model
        } for disk in self.wmi_connection.Win32_DiskDrive()]

        # Network Adapters (only physical adapters)
        self.system_info['network'] = [{
            'name': nic.Name,
            'adapter_type': nic.AdapterType,
            'mac_address': nic.MACAddress,
            'speed': nic.Speed
        } for nic in self.wmi_connection.Win32_NetworkAdapter() 
          if nic.PhysicalAdapter and nic.MACAddress is not None]

        # Motherboard
        for board in self.wmi_connection.Win32_BaseBoard():
            self.system_info['motherboard'] = {
                'manufacturer': board.Manufacturer,
                'product': board.Product,
                'serial_number': board.SerialNumber
            }

    def collect_event_logs(self, days_back=7):
        """Collect system, application, and security event logs."""
        log_types = ['System', 'Application', 'Security']
        self.system_info['event_logs'] = defaultdict(list)
        end_date = datetime.datetime.now()
        start_date = end_date - datetime.timedelta(days=days_back)

        for log_type in log_types:
            handle = win32evtlog.OpenEventLog(None, log_type)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = []
            while True:
                events_batch = win32evtlog.ReadEventLog(handle, flags, 0)
                if not events_batch:
                    break
                for event in events_batch:
                    event_date = datetime.datetime.strptime(str(event.TimeGenerated), '%Y-%m-%d %H:%M:%S')
                    if event_date < start_date:
                        break
                    if event.EventType in [win32evtlog.EVENTLOG_ERROR_TYPE, win32evtlog.EVENTLOG_WARNING_TYPE]:
                        events.append({
                            'source': event.SourceName,
                            'type': 'Error' if event.EventType == win32evtlog.EVENTLOG_ERROR_TYPE else 'Warning',
                            'date': str(event.TimeGenerated),
                            'event_id': event.EventID,
                            'description': str(event.StringInserts)
                        })
                        
            self.system_info['event_logs'][log_type] = events
            win32evtlog.CloseEventLog(handle)

    def generate_report(self):
        """Generate a summarized report of the system analysis."""
        report = []
        
        # Hardware Summary
        report.append("=== Hardware Summary ===")
        
        # CPU Summary
        cpu = self.system_info['cpu'][0]  # Assuming single CPU system
        report.append(f"\nCPU: {cpu['name']}")
        report.append(f"Cores/Threads: {cpu['cores']}/{cpu['threads']}")
        
        # Memory Summary
        total_memory = sum(mem['capacity_gb'] for mem in self.system_info['memory'])
        report.append(f"\nTotal Memory: {total_memory:.2f} GB")
        
        # Disk Summary
        report.append("\nStorage Devices:")
        for disk in self.system_info['disks']:
            report.append(f"- {disk['model']}: {disk['size_gb']:.2f} GB ({disk['interface']})")
        
        # Network Summary
        report.append("\nNetwork Adapters:")
        for nic in self.system_info['network']:
            report.append(f"- {nic['name']} ({nic['mac_address']})")
        
        # Event Log Summary
        report.append("\n=== Event Log Summary (Last 7 Days) ===")
        for log_type, events in self.system_info['event_logs'].items():
            error_count = sum(1 for e in events if e['type'] == 'Error')
            warning_count = sum(1 for e in events if e['type'] == 'Warning')
            report.append(f"\n{log_type} Log:")
            report.append(f"- Errors: {error_count}")
            report.append(f"- Warnings: {warning_count}")
            if error_count > 0:
                report.append("\nMost Recent Errors:")
                errors = [e for e in events if e['type'] == 'Error']
                for error in sorted(errors, key=lambda x: x['date'], reverse=True)[:3]:
                    report.append(f"- {error['date']}: {error['source']} - Event ID: {error['event_id']}")
        
        return "\n".join(report)

    def save_results(self, output_dir="system_analysis"):
        """Save both raw data and report to files."""
        # Create output directory if it doesn't exist
        Path(output_dir).mkdir(exist_ok=True)
        # Save raw data as JSON
        with open(Path(output_dir) / "system_data.json", "w") as f:
            json.dump(self.system_info, f, indent=2)
        # Save report as text file
        with open(Path(output_dir) / "system_report.txt", "w") as f:
            f.write(self.generate_report())

def main():
    analyzer = WindowsSystemAnalyzer()
    print("Collecting hardware information...")
    analyzer.collect_hardware_info()
    print("Collecting event logs from the past 7 days...")
    analyzer.collect_event_logs()
    print("Generating report...")
    analyzer.save_results()
    print("Analysis complete! Check the 'system_analysis' directory for results.")

if __name__ == "__main__":
    main()
