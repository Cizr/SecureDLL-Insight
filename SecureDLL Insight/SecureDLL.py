import psutil
import argparse
import logging
from datetime import datetime
from vt import Client as VirusTotal

    #Function to set up logging configuration
def setup_logging(log_file):
    logging.basicConfig(filename=log_file, level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s')
    
    #Class for interacting with VirusTotal API
class VTIntegration:
    def __init__(self, api_key):
        self.vt = VirusTotal(api_key)
        
    #Method to check a DLL hash with VirusTotal
    def check_dll_hash(self, file_hash):
        try:
            file_report = self.vt.get_file_report(file_hash)
            if file_report['response_code'] == 1:
                return file_report
        except Exception as e:
            logging.error(f"Error querying VirusTotal: {str(e)}")
        return None

def get_processes_with_dlls(process_names, vt_integration):
    processes_with_dlls = []

    for proc in psutil.process_iter(['name', 'pid', 'cmdline']):
        try:
            if proc.info['name'] in process_names and proc.info['cmdline'] is not None and len(proc.info['cmdline']) > 1:
                process_data = (proc.info['name'], proc.info['pid'], ' '.join(proc.info['cmdline'][1:]))
                processes_with_dlls.append(process_data)

                # Check DLL hash with VirusTotal
                dll_path = proc.info['cmdline'][1]  # Assuming the DLL path is the first argument
                dll_hash = calculate_file_hash(dll_path)
                file_report = vt_integration.check_dll_hash(dll_hash)
                if file_report:
                    print(f"VirusTotal Report for {dll_path}: {file_report}")

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    return processes_with_dlls
    #Function to calculate the SHA256 hash of a file
def calculate_file_hash(file_path):
    import hashlib
    sha256 = hashlib.sha256()

    with open(file_path, 'rb') as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256.update(byte_block)

    return sha256.hexdigest()

    #Function to print information about processes with DLLs
def print_processes_with_dlls(processes_with_dlls):
    if processes_with_dlls:
        print("Processes with DLLs:")
        for process in processes_with_dlls:
            name, pid, args = process
            print(f"Name: {name}\tPID: {pid}\tCommand Line Arguments: {args}")
            logging.info(f"Name: {name}\tPID: {pid}\tCommand Line Arguments: {args}")
    else:
        print("No processes with DLLs found.")
        logging.info("No processes with DLLs found.")
        
    #Main function of the script
def main():
    parser = argparse.ArgumentParser(description='DLL Hunter - Identify processes with DLLs.')
    parser.add_argument('--logfile', default='dll_hunter.log', help='Path to the log file.')
    parser.add_argument('--vtapikey', required=True, help='VirusTotal API key.')
    args = parser.parse_args()

    setup_logging(args.logfile)

    process_names = [
        'rundll32.exe', 'regsvr32.exe', 'regsvcs.exe', 'regasm.exe',
        'certoc.exe', 'dnscmd.exe', 'installutil.exe', 'mavinject32.exe',
        'msiexec.exe', 'netsh.exe', 'pcalua.exe', 'rasautou.exe',
        'register-cimprovider.exe', 'acccheckconsole.exe', 'coregen.exe',
        'dotnet.exe', 'procdump.exe', 'tracker.exe', 'vsls-agent.exe',
        'wuauclt.exe'
    ]

    vt_integration = VTIntegration(api_key=args.vtapikey)

    processes_with_dlls = get_processes_with_dlls(process_names, vt_integration)
    print_processes_with_dlls(processes_with_dlls)

if __name__ == '__main__':
    main()
