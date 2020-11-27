
<h1>Capstone Engagement</h1>
<p>&nbsp;</p>

<h1>Assessment, Analysis, and Hardening of a Vulnerable System</h1>
<p>&nbsp;</p>
<p>&nbsp;</p>

<h2>Table of Contents</h2>

    1. Network Topology

    2. Red Team: Security Assessment

    3. Blue Team: Log Analysis and Attack Characterization

    4. Hardening: Proposed Alarms and Mitigation Strategies

<p>&nbsp;</p>
<h2>Section 1: Network Topology</h2>
<p>&nbsp;</p>
<h4>Network Topology Diagram</h4>

![Network Diagram](/Images/Network-Diagram.png)
<p>&nbsp;</p>
<h4>Subnet</h4>

    Network Address Range: 192.168.1.0/24
    Netmask:255.255.255.0
    Gateway:192.168.1.1
    
<p>&nbsp;</p>
<h4>Machines</h4>

IPv4 | OS | Hostname 
------------ | ------------- | -------------
192.168.1.1 | Windows 10 Pro | Jump Host
192.168.1.90 | Kali Linux | Kali
192.168.1.100 | Linux | ELK
192.168.1.105 | Linux | Capstone

<p>&nbsp;</p>
<p>&nbsp;</p>
<h2>Section 2: RED TEAM </h2>
<p>&nbsp;</p>
<p>&nbsp;</p>

<h2>SECURITY ASSESSMENT</h2>
<p>&nbsp;</p>

<h3>Recon: Describing the Target</h3>

Nmap identified the following hosts on the network:

Hostname | IP Address | Role on Network 
------------ | ------------- | -------------
ELK Server | 192.168.1.100 | ELK Server; 9200/tcp open wap-wsp
Capstone | 192.168.1.105 | Capstone Corporate Server; 80/tcp open http
Kali  | 192.168.1.90 | Pen Test Station; 22/tcp open ssh
Jump Host | 192.168.1.1 | Jump Host; 2179/tcp open vmrdp

<p>&nbsp;</p>
<h2>VULNERABILITY ASSESSMENT</h2>
<p>&nbsp;</p>
The assessment uncovered the following **critical** vulnerabilities in the target:

<h4>Vulnerability 1<h4>
<b>CVE 2007-5461</b>

    Description:
    Apache Tomcat -'WebDAV' Remote File Disclosure

    Impact:
    A remote authenticated user could read arbitrary files and write request via WebDAV, potential for loss of sensitive data.


<h4>Vulnerability 2</h4>
<b>CVE 2017-15715</b>

    Description:

    Local File Inclusion (LFI)
    allows an attacker to read and likely execute files other than those intended to be served by the machine

    Impact:

    An LFI vulnerability allows attackers to gain access to sensitive credentials


<h4>Vulnerability 3</h4>
<b>CWE 521: Weak Password</b>

    Description:

    Weak passwords are vulnerable to being matched quickly with commonly available tools.

    Impact:

    Accounts are vulnerable to being exploited and providing attackers authenticated access to the network.


<h4>Vulnerability 4</h4>
<b>CWE 307: Improper restriction of excessive authentication attempts</b>

    Description:

    No password lockout policy in place

    Impact:

    An attacker is free to continually attempt to guess a password utilising brute force means.


<h4>Exploitation 1: WebDAV file disclosure</h4>

    1.1 Tools & Processes
    With the access credentials known, we authenticated via browser and the files in WebDAV were available.

    1.2 Achievements
    Detail of a secure password contained in passwd.dav exposed remotely.
    Apache version displayed.

    1.3 Exploitation Evidence
    
  ![WebDAV file disclosure](/Images/WebDav-file-disclosure.png)
    

<h4>Exploitation 2: No account lockout</h4>

    2.1 Tools & Processes
    The vulnerability was exploited using hydra, a brute force password matching tool.     
    A password list file, rockyou.txt, was downloaded and utilised.

    2.2 Achievements
    The password for the account of ashton was determined in short order.
    The account provides access to the “secret_folder” and flag.txt

    2.3 Exploitation Evidence
    
    Screenshots of flag.txt and the hydra tool, displaying the command executed and results:
    
  ![flag](/Images/flag.png)
  
  ![No account lockout](/Images/No-account-lockout.png)
  
    

<h4>Exploitation 3: Local File Inclusion</h4>

    3.1 Tools & Processes
    The Metasploit framework was used to create .php packaged exploits, 
    which were copied to the machine using curl.

    A local listener is set up. The php is executed and a session is opened.

    3.2 Achievements
    A remote session was achieved on the target machine. Reverse shell available

    3.3 Exploitation Evidence
    
    Screenshots of exploits 
    
  ![(i) Local File Inclusion](/Images/LFI-1.png)
  ![(ii) Local File Inclusion](/Images/LFI-2.png)
    

<p>&nbsp;</p>
<p>&nbsp;</p>
<h2>Section 3: BLUE TEAM </h2>
<p>&nbsp;</p>
<p>&nbsp;</p>
<h2>Log Analysis and Attack Characterization</h2>
<p>&nbsp;</p>

<h4>Analysis: Identifying the Port Scan</h4>

![Port Scan Graph](/Images/PortScanGraph.png)
![Port Scan Events](/Images/PortScanEvents.png)

    ● The port scan occurred around 04:45 am; 200 packets were sent from source IP 192.168.1.90, agent.hostname:Kali

    ● The activity moved from port to port, indicating that this was a port scan
    

<h4>Analysis: Finding the Request for the Hidden Directory</h4>

![Request for the Hidden Directory](/Images/HiddenDir.png)

    ● There were 2 requests at 10:59 on Nov 17

    ● connect_to_corp_server is the filename. It contains details on how to connect to the /WebDAV share,
    including a hash of ryan's password.

<h4>Analysis: Uncovering the Brute Force Attack</h4>

![Brute Force Attack](/Images/BruteForceAttack-stats.png)

● 11171 requests were made in the attack

● 11170 requests had been made before the attacker discovered the password

<h4>Analysis: Finding the WebDAV Connection</h4>

Kibana Search

*source.ip : 192.168.1.90 and http.response.status_code : 200 and url.full : "http://192.168.1.105/webdav/"*

![The WebDAV Connection](/Images/WebDAV-connection.png)

    ● Requests made to this directory; count = 30
    
    ● Successful requests were made for the files passwd.dav and shell.php


<h2>Section 4: Hardening </h2>
<p>&nbsp;</p>
<h2>Proposed Alarms and Mitigation Strategies - Blue Team </h2>

<h4>Alarm </h4>

    Mitigation: Blocking the Port Scan

    We need to detect future port scans and alarm on detection.

    We can monitor the logs of recently dropped packets (iptables) and 
    have a tool take action based on the threshold.

    I would suggest a threshold of; 10 hits within 60 seconds to activate this alarm.

    Inotify-tools is an open source method for monitoring and setting actions


<h4>System Hardening</h4>

    Linux iptables can be configured to DROP tcp packets based on the threshold;

    $IPT -A INPUT -p tcp –syn -m recent

        name portscan –rcheck –seconds 60
        hitcount 10 -j LOG
        $IPT -A INPUT -p tcp –syn -m recent
        name portscan –set -j DROP

    It is good practice to drop all traffic by default

        iptables -P INPUT DROP
        iptables -P FORWARD DROP
        iptables -P OUTPUT DROP
    
    however we then need to specify rule chains for permitted services from and to 
    authorised addresses or subnets.
    
....

    Reference:
    https://meterpreter.org/how-to-prevent-port-scan-in-linux/


<h4>Alarm </h4>

    Mitigation: Finding the Request for the Hidden Directory

    We could set an alarm with audit.d to inform us when this file is accessed in future.

    To make changes persistent, add them to the /etc/audit/audit.rulesfile

        w company_folders/secret_folder/
        connect_to_corp_server -p war -k
        connect_to_corp

        # w: watch. 
        # p: permission you want to audit/watch, r for read, w for write, x for execute, a for append
        # k: keyword for this audit rule

    In this case, the alarm threshold should be 2 hits per day.


<h4>System Hardening</h4>

    Requiring simply a username / password combination is not adequate.

    We should adopt certificate based authentication for the hidden directory.

    Only clients with a valid certificate installed will then be able to access the hidden directory.

        openssl x509 -req -days 365 -in server.csr -
        signkey server.key -out server.crt
        sudo cp server.crt /etc/ssl/certs
        sudo cp server.key /etc/ssl/private

    We then need to configure our applications to use the certificate. 

    This will also make the application traffic run with a secure protocol; https with SSL/TLS encryption
    
....

References:	
   
   https://www.thegeekdiary.com/how-to-audit-file-access-on-linux/
    
   https://ubuntu.com/server/docs/security-certificates


<h4>Alarm </h4>

    Mitigation: Preventing Brute Force Attacks

    Brute force attacks involve a high volume of requests. 
    We should establish a baseline of normal activity around a resource and report on volume anomalies.

    With a normal activity level of say 50 requests per hour, the activity may be condensed to a shorter period,
    especially after a break.

    A threshold of 100 requests per 5 minute period would activate this alarm and not be triggered by normal activity.


<h4>System Hardening</h4>

    Blocking brute force attacks on passwords can be accomplished by locking out an account after say three failed requests.

    We should have an enterprise account policy that enforces this (and enforce stronger passwords). 

    Another means is to return an non-standard response to failed logins, return a 200 success code with a page for
    “failed login”, instead of the standard 401 error.

    Also, after a failed login attempt we should prompt the user to answer a secret question.
    This would prevent even a known password being used at this time.
    
....

Reference:

   https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks


<h4>Alarm</h4>

    Mitigation: Detecting the WebDAV Connection

    Detecting future access to this directory could be accomplished within existing infrastructure using packet beats,
    with a focus on http requests to /WebDAV or via auditd.

    The threshold set to activate this alarm would be based on normal usage. 

    For example; if we have 10 users daily and some may request the file (http GET) more than once,
    I would set the alarm threshold at a count 16 in 10 hours. 

    We should alarm on every http PUT request, other than those from an authorised IP address.


<h4>System Hardening</h4>

    IP whitelisting; setting configuration on the host to control access could be done using an iptables rule set
    that allows requests and responses only from and to a listed IP.

    Whitelist IP address 10.25.44.23

    - allow incoming connections from workstation IP

    iptables -A INPUT -s 10.25.44.23 -j ACCEPT.

    - allow outgoing connections to workstation IP

    iptables -A OUTPUT -d 10.25.44.23 -j ACCEPT
    
....

Reference: 
   
   https://help.serversaustralia.com.au/s/article/How-To-Whitelist-An-IP-Address-In-IPTables



<h4>Alarm </h4>

    Mitigation: Identifying Reverse Shell Uploads

    Setting an alarm -assuming the upload is rare, we should alert on every http PUT request. 

    Where uploads are routine, every http PUT request from an unauthorised IP address should alarm.

    We can set an alarm that targets specific file types, being those that are not normal for the shared folder. 

    A baseline of normal activity and a threshold of normal times two would be a reasonable threshold
    at which to activate this alarm.

    For .php files, we should alert for every attempt; set threshold at 1.


<h4>System Hardening</h4>

    We can use specific local configuration to extend the functionality of Apache.

    Placing a configured .htaccess file in a web server directory will affect all files, folders and sub-directories.

    Specifically to deny a .php file to be run we insert this configuration block into our .htaccess file

        <Files *.php>
        deny from all
        </Files>
 
 ....
 
References:	

    https://serverfault.com/questions/677633/how-can-i-disable-specific-file-type-uploads-globally-in-apache
    
    http://www.htaccess-guide.com/  
    
<p>&nbsp;</p>
<p>&nbsp;</p>
<h3>IMPORTANT</h3>

    The Penetration Test uncovered that one employee is using the password of another to access corporate information.

    In line with best-practice, strict role-based access controls should be enforced,
    including revoking access for those that no longer perform that role.

    Reference: https://owasp.org/www-community/Access_Control
<p>&nbsp;</p>
<p>&nbsp;</p>
<h3>END</h3>


