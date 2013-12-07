""" Project Byzantium: captive-portal.sh
This script does the heavy lifting of IP tables manipulation under the captive portal's hood.  It should only be used by the captive portal daemon. """

__authors__ = ["Sitwon", "The Doctor", "haxwithaxe"]
__license__ = "GPLv3"

import iptc

bit_to_cidr_mask = ["0", "128", "192", "224", "240", "248", "252", "254"]

class IPTablesUtil:
	def __init__(self):
		self.address = ""
		self.mask = 32
		self.net_block = ""

	def _get_netblock_from_address(self):
		""" Convert the IP address of the client interface into a netblock. """
		if self.mask < 0 or sel.mask > 32:
			return None
		address = self.address.split(".")
		mask = sel.mask
		while mask > 0:
				if mask%8 != 0:
					address[mask/8] = "0"
				mask -= 8

		self.net_block = ".".join(address)

class Chains:
	PREROUTING = "PREROUTING"
	FORWARD = "FORWARD"
	INPUT = "INPUT"
	PORTAL = "PORTAL"
	DNAT = "DNAT"
	SNAT = "SNAT"

iptc_policies = [iptc.Policy.ACCEPT, iptc.Policy.DROP, iptc.Policy.QUEUE, iptc.Policy.RETURN]

class RuleSpec:
	def __init__(self, table = iptc.Table.ALL, chain = None, protocol = None, 
			match = None, mark = None, iface_in = None, iface_out = None, 
			dest = None, dest_port = None, src = None, src_port = None, 
			policy = None):
		self.table = iptc.Table(table)
		self.chain = iptc.Chain(self.table, chain)
		self.protocol = protocol
		self.match = match
		self.mark = mark
		self.iface_in = iface_in
		self.iface_out = iface_out
		self.dest = dest
		self.dest_port = dest_port
		self.src = src
		self.src_port = src_port
		self.policy = policy

	def _set_rule(self):
		if self.iface_in:
			self.rule.in_interface = self.iface_in
		if self.iface_out:
			self.rule.out_interface = self.iface_out
		if self.src:
			self.rule.src = self.src
		if self.protocol:
			self.rule.protocol = rule.protocol
		if self.target:
			self.rule.create_target(self.target)

	def _set_matches(self):
		if self.matches:
			for m in self.matches:
				match = self.rule.create_match(m)
				if isinstance(self.dest_port, int):
					match.dport = self.dest_port
				if self.mark:
					self.match.mark = self.mark

	def _set_target(self):
        table = iptc.Target(self.rule, self.target)

    def add(self):
		self._set_rule()
		self._set_matches()
		table = iptc.Target(self.rule, self.target)
		

def exempt_nonclient_traffic():
	"""Exempt traffic which does not originate from the client network.
	$IPTABLES -t mangle -A PREROUTING ! -s $CLIENTNET -j RETURN """
	RuleSpec(table=iptc.Table.MANGLE, chain=PREROUTING, conditons={"src":Not(client_net)}, policy=iptc.Policy.RETURN)

def grab_new_clients():
	""" Traffic not exempted by the previous rules gets kicked to the captive portal chain.  When a user clicks through a rule is inserted before this one that matches them with a RETURN.
	$IPTABLES -t mangle -A PREROUTING -j internet"""
	RuleSpec(table=iptc.Table.MANGLE, chain=chain.PREROUTING,  policy=chain.PORTAL)

def get_client_mac(self, client_addr):
	""" CLIENTMAC=`$ARP -n | grep ':' | grep $CLIENT | awk '{print $3}'` """
	arp(client_addr)

def mark_unrecognized():
	""" Traffic not coming from an accepted user gets marked 99.
	$IPTABLES -t mangle -A internet -j MARK --set-mark 99 """
	RuleSpec(table=iptc.Table.MANGLE, chain=chain.PORTAL, policy=MARK, mark=99)

def redirect_marked(rule, protocol, port, client_addr, dest_port):
	""" $IPTABLES -t nat -A $rule -d $client_net -p $proto --sport $port -j SNAT --to-source :$sport """
	RuleSpec(table=iptc.Table.NAT, dest=client_netblock, protocol=protocol, src_port=src_port, policy=chain.SNAT, in_port=src_port)

def allow_captive_traffic_to_portal(client_addr):
	""" Traffic which has been marked 99 and is headed for 80/TCP or 443/TCP should be redirected to the captive portal web server. """
    redir_marked(protocol="tcp", dest_port=80, src=client_addr, to_port=31337)
    redir_marked(protocol="tcp", dest_port=443, src=client_addr, to_port=31338)
    redir_marked(protocol="udp", dest_port=53, src=client_addr, to_port=31339)

def redirect_marked_for_portal(client_netblock):
	"""  """
	# HTTP replies come from the same port the requests were received by.
	# Rewrite the outbound packets to appear to come from the appropriate ports.
    iptables_unredir_marked(protocol="tcp", src_port=31337, dest=client_netblock, to_port=80)
    iptables_unredir_marked(protocol="tcp", src_port=31338, dest=client_netblock, to_port=443)
    # Replies from fake_dns.py come from the same port because they're
    # UDP.  Rewrite the packet headers so it loose like it's from port
    # 53/udp.
    iptables_unredir_marked(protocol="udp", src_port=31339, dest=CLIENTNET, to_port=53)

def drop_nonexempt_marked():
	""" add iptables rule to drop traffic which is marked "99". """
	RuleSpec(table=iptc.Table.FILTER, target=FORWARD, match={"name":"mark", "mark-source":99}, policy=iptc.Policy.DROP)

def allow_incoming():
	""" add an iptables rule to allow incoming traffic in general """
	RuleSpec(table=iptc.Table.FILTER, target=target.INPUT, policy=iptc.Policy.ACCEPT)

def add_client():
	""" add an iptables rule to allow a client past the captive portal """
    # Add the MAC address of the client to the whitelist, so it'll be able to access the mesh even if its IP address changes.
	RuleSpec(table=iptc.Table.MANGLE, out_interface=internet, match={"name":"mac", "mac-source":CLIENTMAC}, policy=iptc.Policy.RETURN)

def remove_client(client_addr):
	""" remove iptables rule for hosts  """
    # Isolate the MAC address of the client in question.
    client_mac = get_client_mac(client_addr)
    # Delete the MAC address of the client from the whitelist.
	RuleSpec(table=iptc.Table.MANGLE, chain=internet, match={"name":"mac", "mac-source":client_mac}, policy=iptc.Policy.RETURN)

def flush_chains(table):
	""" flush the rules in the chains specified """
	for chain in table.chains:
		chain.flush()

def flush_tables(*tables):
	""" flush the rules in the tables specified """
	for table in tables:
		table = iptc.Table(table)
		flush_chains(table)
		table.flush()

def flush_all():
    """ Purge all of the IP tables rules. """
	flush_tables(iptc.Table.ALL)

def list_rules(*tables):
    """ Display the currently running in the given tables. """
	rules = []
	for table in tables:
		for chain in table.chains:
			rules += chain.rules

def init_mangle():
	""" Initialize the IP tables ruleset by creating a new chain for captive
    portal users.
	$IPTABLES -N internet -t mangle """
	mangle = iptc.Table(iptc.Table.MANGLE)
	chain.PORTAL = mangle.creat_chain("portal")

def init_captive_portal():
	"""  """
	# Initialize the IP tables ruleset by creating a new chain for captive portal users.
    init_mangle()
	# Convert the IP address of the client interface into a netblock.
    client_netblock = get_netblock_from_address(client_addr, bit_mask)
    # Exempt traffic which does not originate from the client network.
    exempt_nonclient_traffic()
    # Traffic not exempted by the above rules gets kicked to the captive
    # portal chain.  When a use clicks through a rule is inserted above
    # this one that matches them with a RETURN.
    grab_new_clients()
    # Traffic not coming from an accepted user gets marked 99.
	mark_unrecognized()
    # Traffic which has been marked 99 and is headed for 80/TCP or 443/TCP should be redirected to the captive portal web server.
    redirect_marked_to_portal()
    # HTTP replies come from the same port the requests were received by.
    # Rewrite the outbound packets to appear to come from the appropriate
    # ports. Also replies from fake_dns.py come from the same port because
    # they're UDP.  Rewrite the packet headers so it loos like it's from port
    # 53/udp.
    redirect_marked_from_portal()
    # All other traffic which is marked 99 is just dropped
	drop_marked()
    # Allow incoming traffic that is headed for the local node.
    allow_incoming
    # But reject anything else coming from unrecognized users.
	reject_unregistered_clients()

def drop_marked():
	""" All other traffic which is marked 99 is just dropped """
    RuleSpec(table=iptc.Table.FILTER, target=chain.FORWARD, match={"name":"mark", "mark":99}, policy=iptc.Policy.DROP)

def reject_unregistered_clients():
	"""  """
	RuleSpec(table=iptc.Table.FILTER, target=chain.INPUT , match={"name":"mark", "mark":99}, policy=iptc.Policy.DROP)

def handle_args(args):
	# Set up the choice tree of options that can be passed to this script.
	if args.initialize:
		# IP address of the client interface.  Assumes final octet is .1.
		init_captive_portal(args.client, bit_mask=args.bit_mask)
	if args.add:
		# IP address of client.
	    add_client=args.client
	if args.remove:
		# IP address of client.
		remove_client=args.client
	if args.purge:
		# Purge all of the IP tables rules.
		iptables_purge()
	if args.list:
		# Display the currently running IP tables ruleset.
		iptables_list()

"USAGE: %s {initialize <IP> <interface>|add <IP> <interface>|remove <IP> <interface>|purge|list}" % sys.agrv[0]
