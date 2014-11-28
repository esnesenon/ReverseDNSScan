#!/usr/bin/python
# reverse_dns_scan.py

from scapy.all import DNSQR, UDP, IP, sr1
from optparse import OptionParser

parser = OptionParser()
parser.add_option("-t", "--target", desc="Target host or network segment to scan. Can specify x.y.z.w/mask or x.y.z.w. Does not yet support masks other than 8, 16, 24, 32", default="8.8.8.8/32")
parser.add_option("-s", "--server", desc="DNS server to send requests to", default="8.8.8.8")
parser.add_option("-v", "--verbose", desc="Enable verbose mode - prints debug information to stdout")

(opts, args) = parser.parse_args()

def scan(target, server):
	verbose_trace("Starting scan - preparing IP addresses for use")
	
	try:
		prepared_address = prepare_address(opts.target)
	except Exception as e:
		print("Failed to prepare addresses for scan. Exiting..\n")
		verbose_trace("Exception details: {0}".format(e))
		exit(1)
	
	verbose_trace("Setting up DNS packets")
	packets = IP(dst=prepared_address)/UDP()/DNS(rd=1, qd=DNSQR(qname=prepared_address, qtype='PTR'))
	
	verbose_trace("Sending packets")
	results = sr1(packets)
	
	[result.show() for result in results]
	exit(0)
	
	
def prepare_address(address):
	if address is None:
		raise Exception("Can not prepare null address")
	
	try:
		octets = address.split('.')
		last_octet, mask = octets[3].split('/')
		
		if int(mask) == 32:
			return last_octet + '.' + octets[2] + '.' + octets[1] + '.' + octets[0] + '.in-addr.arpa'
		elif int(mask) == 24:
			return [fourth_octet + '.' octets[2] + '.' + octets[1] + '.' + octet[0] + '.in-addr.arpa' for fourth_octet in range(0, 254)]
		elif int(mask) == 16:
			return [fourth_octet + '.' + third_octet + '.' + octets[1] + '.' + octets[0] + '.in-addr.arpa' \
			for fourth_octet in range(0, 254)] for third_octet in range(0, 254)]
		elif int(mask) == 8:
			return [[[fourth_octet + '.' + third_octet + '.' + second_octet + '.' + octets[0] + '.in-addr.arpa' \
			for fourth_octet in range(0, 254)] for third_octet in range(0, 254)] for second_octet in range(0, 254)]
		else:
		
	except Exception as e:
	
if __name__ == __main__:
	if opts.target is None or opts.server is None:
		print("Bad arguments. Expected both nonempty target and server. Exiting..")
	
	if opts.verbose == True:
		debug = True
	else:
		debug = False
		
	if debug == True:
		def verbose_trace(msg):
			print("\t[TRACE]:: {0}\n".format(msg))
	else:
		def verbose_trace(msg):
			pass
	
	scan(opts.target, opts.server)
	exit(0)