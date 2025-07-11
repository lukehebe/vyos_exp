This Python script is a custom reimplementation of the Metasploit module exploit for CVE-2018-1049, which targets VyOS (Vyatta) via a privilege escalation vulnerability in a Perl script misused through sudo. Authenticated RCE.
You need valid SSH credentials.
You gain root via command injection in a sudo-permitted script.
Even though it targets a local script, the exploit is launched remotely over SSH
