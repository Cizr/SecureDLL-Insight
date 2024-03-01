# SecureDLL-Insight
This script is like a detective for your computer. It looks at what programs are running, especially those using special files. It then asks an expert (VirusTotal) if these files are safe or not. The goal is to catch and report any suspicious or harmful activity on your computer.

## What the Script Does:
Looks at Running Programs: The script looks at all the programs currently running on a computer.

Checks for Suspicious Programs: It pays special attention to programs that are often associated with potential security issues, like certain types of viruses or attacks.

Checks for Special Files (DLLs): These programs, focus on those that are using special files called DLLs (Dynamic Link Libraries). DLLs are files that programs use to share code and resources.

Asks VirusTotal for Help: For each program using a DLL, the script calculates a special code (hash) for that DLL file. Then, it asks an online service called VirusTotal for information about that code.

Reports Findings: If VirusTotal has information about the code and it looks suspicious, the script tells you about it. This helps to identify potentially harmful programs on the computer.

Keeps a Record: The script also keeps a log, like a diary, of what it finds and what it checks, which can be useful for later analysis.

# Why the VirusTotal API Key ?

The VirusTotal service has a lot of information about different programs and files, especially whether they are known to be harmful.
The API key is like a key to access this information. It allows the script to ask VirusTotal questions about the DLL files and get more details.

## Real-Life Scenario
As a system administrator, you want to ensure the security of Windows machines in your network. Periodically, you run SecureDLL to scan for suspicious DLL-related activity on critical processes. For instance, you can quickly identify potential threats like DLL injections in common processes such as rundll32.exe or mavinject32.exe. The integration with VirusTotal API enhances your security posture by cross-referencing DLL hashes against a vast threat intelligence database. This straightforward tool helps you maintain a vigilant eye on potential security risks across your Windows environment.

## Prerequisites
Before using the script, ensure you have the following:

- Python 3.x installed on your system.
- The required Python packages installed. You can install them using:
  ```bash
  pip install psutil argparse vt


## Obtain a VirusTotal API key.
Visit VirusTotal and sign up for an account.
Retrieve your API key from the VirusTotal API Settings page.
Run the script.
 ```
python dll_process_hunt.py --logfile dll_hunter.log --vtapikey YOUR_VIRUSTOTAL_API_KEY
 ```

## Command-Line Options
--logfile: Specifies the path to the log file. The default is logfile.log.
--vtapikey: Specifies the VirusTotal API key (required).
