# PCAP (Pcap Content Analysis and Processing)

PCAP will eventually allow for a wide variety of useful automated analysis. Right now it only supports analyzing webhosts via GET request.
The results are then emailed via gmail to you. A Gmail account and Virus Total API key is required for the program to function. Must be converted to .jar before use using an ide.

Current Features:  
As stated earlier PCAP can only go through PCAPs and figure out what websites host are downloading stuff from. This is done by looking at the packet payload since is not encrypted. Looks at destination ports 80 and 8080. Found webhost are sent to Virus Total for analysis and can then be retrieved at a later time. Reports are emailed. 

Future Features:  
ARP flooding detection  
SQL injection detection  
Port scanning detection  
and more  
