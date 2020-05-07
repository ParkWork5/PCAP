# PCAP (Pcap Content Analysis and Processing)

PCAP will eventually allow for a wide variety of useful automated analysis A Gmail account and Virus Total API key is required for the program to function. Must be converted to .jar before use using an ide. Gmail account will also need to allow access to less secure apps even through I use TLS in PCAP.

Current Features:  
1.  
As stated earlier PCAP can currently go through PCAPs and figure out what websites host are downloading stuff from via GET request. This is done by looking at the packet payload since is not encrypted. Found webhost are sent to Virus Total for analysis and can then be retrieved at a later time. Reports are emailed.
2.  
ARP spoofing analysis now works. Parses ARP packet for source ip and mac address. Then maps ips to mac address and then counts the ips mapped to each mac address. If greater than 1 it gets flagged as spoofing. Report is automatically generated and sent to Gmail. 
  
Current Flags:  
-pcappath [pcap file path] //Sets pcap file path  
-vtapi [Virus total api key] //Sets Virus total api key to use in program  
-help //Shows help menu  
-email [Dest email] // Sets email for recieving report  
-emailPassword [Password] // Sets email password  
  
Example:  
java -jar pcap.jar -pcappath /home/pcap/path -vtapi apikeyhere -email Gmail@here -emailPassword Gmailpassword
  
Future Features:    
SQL injection detection  
Port scanning detection  
and more  
