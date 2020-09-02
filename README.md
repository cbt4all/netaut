Network Automation provides generic and vendor specific tools to config/monitor networking devices
For example it can use ssh or REST API to multiple devices and run template configs.

At the moment there are three packages working (still under develop)
- fwcom (Firewall Common): Includes common stuff may be used while dealing with all firewalls. For example read from CSV file to see what is needed and convert it to the format: Srouce IP, Destination IP, Destination Port and Application. This information is always used in firewalling
- generic: Includes all things that can be used on all networking devices, regardless of the vendor. For example, SSH to the device.
- paloalto: Includes all things relate to Palo Alto devices. It can be Palo Alto customized SSH or REST API, etc

Next step will be Juiper, Fortinet, Cisco, Checkpoint