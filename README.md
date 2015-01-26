DESCRIPTION
===========
This module is used to exploit startup script execution through Windows Group
Policy settings when configured to run off of a remote SMB share.

Windows Group Policy can be used to configure startup scripts that will execute
each time the operating system powers on. These scripts execute with a
high-level of privilege, the NT AUTHORITY/SYSTEM account.

If an attacker is able to perform traffic manipulation attacks and redirect 
traffic flow to the malicious SMB server during reboot, it is possible to
execute commands remotely as the SYSTEM account. 

This module will accept all forms of authentication whether that be anonymous,
domain, blank password, non-existent accounts. It will allow any user to connect
to the SMB server and share. 

It will also perform file spoofing and serve up the same file regardless
of what file was originally requested, and regardless of which SMB share the 
client is connected to. If the user requests foo.vbs it will send them evil.vbs. 

This was tested on Windows 7 Service Pack 1 (x86) using .bat and .vbs scripts. 

Blog Post:
 "BadSamba - Exploiting Windows Startup Scripts Using A Malicious SMB Server" - 
  http://blog.gdssecurity.com/labs/2015/1/26/badsamba-exploiting-windows-startup-scripts-using-a-maliciou.html

LIMITATIONS
===========
- BadSamba has been tested using .bat and .vbs remote script includes. The file
  extension does seem to matter, so if it’s requesting a .bat, serve up a .bat.

- In the lab environment, testing has been against Windows 7 SP1 (English) for
  the proof-of-concept. Different versions of Windows may react differently,
  but the principal concepts should remain the same.

- It’s not currently possible to "Browse" the files within the SMB share. This
  is due to the complexity of the SMB protocol, and adding this functionality
  would greatly increase the complexity of the module.

- The protocol is quite noisy, and so it can be difficult to determine if the
  file was successfully downloaded or if it was download and executed.

- Currently there is no exclusive lock on files being requested, and this 
  allows for the file to be downloaded multiple times. In my experience, it
  only gets executed once, but it does make for noisy output within the module.
