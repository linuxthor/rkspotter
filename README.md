# Rootkit Spotter
![](rootkit-spotter-logo.png)    

The paper "Effectiveness of Linux Rootkit Detection Tools" by Juho Junnila (http://jultika.oulu.fi/files/nbnfioulu-202004201485.pdf) makes it clear that current Linux rootkit detection tools (except perhaps LKRG) don't do a great job!    

The most alarming statement is that __**"37.3% of detection tests didn't provide any indication of a rootkit infection"**__      

Rootkit spotter is an experimental **proof of concept** LKM showing the use of a few different techniques to try and detect/locate certain types of **known** rootkits in a running system.   

Rootkit spotter can detect some **known** and **unknown** rootkits (using **known** techniques) by looking for anomalies associated with the use of rootkit techniques (e.g LKM hiding and syscall table patching)  

Rootkit spotter does not try in any way to guard itself against malware that attempts to circumvent or bypass it. 

Rootkit spotter is **proof of concept** (see N.A.S.T.Y warning below!) Use it to play and study anti-rootkit. Don't run it on your important stuff in production and get sad when something bad happens!    

### Identifying hidden/tampered modules 

The running kernel is checked for Loadable Kernel Modules. All LKMs that are identified have their module struct checked for signs of tampering such as removal or resetting of certain fields. This should cover the main methods of module hiding and hopefully allow the address, size and name of a hidden kernel module to become known. 

### Identifying known bad LKM using signatures    

Each loadable kernel module in the running kernel is checked for patterns in the code or data sections associated with **known** rootkits. This area of the program currently has a _small number of signatures_ associated with some of the more prominent Linux LKM rootkits (enough to show how it could work - not intending to cover every rootkit ever)     

### Identifying suspicious sys_call_table entries    

Many rootkits for the last 20 years have hooked certain functions by overwriting entries in the syscall table. For a handful of functions that are sometimes patched by rootkits we check to see if the sys_call_table entry is pointing to code that appears to live in an LKM. 

### Identifying userspace LD_PRELOAD rootkits

Userspace rootkits almost always work by the very well known LD_PRELOAD library preloading method. All running processes have their environment checked for LD_PRELOAD environment variable and also the file /etc/ld.so.preload is checked to see if it exists and is non-zero size.  

## Important! N.A.S.T.Y warning! 

_"..**N**ot **a** **s**ecurity **t**ool **y**eah?.."_

This is a proof of concept to show a couple of different techniques. If you want to fork it and make it a full tool then please go ahead! **I'd be sad to learn that you're using it on your important systems as-is!** 
