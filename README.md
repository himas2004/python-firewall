# Python Firewall
  This is a simple Python-based firewall that monitors and blocks packets from specified IP addresses.

# How It Works
- Uses Scapy to sniff packets
- Checks if source/destination IP is in the blocked list
- Prints "BLOCKED" or "ALLOWED" messages

# Run
Run with admin/root:
  python firewall.py
