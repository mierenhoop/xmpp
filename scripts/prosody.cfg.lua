admins = { "admin@localhost" }
--plugin_paths = { "/usr/local/lib/prosody/modules" }
modules_enabled = {
		--"disco"; -- Service discovery
		--"roster"; -- Allow users to have a roster. Recommended ;)
		"saslauth"; -- Authentication for clients and servers. Recommended if you want to log in.
		--"tls"; -- Add support for secure TLS on c2s/s2s connections
		--"blocklist"; -- Allow users to block communications with other users
		--"bookmarks"; -- Synchronise the list of open rooms between clients
		--"carbons"; -- Keep multiple online clients in sync
		--"dialback"; -- Support for verifying remote servers using DNS
		--"pep"; -- Allow users to store public and private data in their account
		--"private"; -- Legacy account storage mechanism (XEP-0049)
		--"smacks"; -- Stream management and resumption (XEP-0198)
		--"vcard4"; -- User profiles (stored in PEP)
		--"vcard_legacy"; -- Conversion between legacy vCard and PEP Avatar, vcard
		--"csi_simple"; -- Simple but effective traffic optimizations for mobile devices
		--"invites"; -- Create and manage invites
		--"invites_adhoc"; -- Allow admins/users to create invitations via their client
		--"invites_register"; -- Allows invited users to create accounts
		--"ping"; -- Replies to XMPP pings with pongs
		--"register"; -- Allow users to register on this server using a client and change passwords
		--"time"; -- Let others know the time here on this server
		--"uptime"; -- Report how long server has been running
		--"version"; -- Replies to server version requests
		--"mam"; -- Store recent messages to allow multi-device synchronization
		--"admin_adhoc"; -- Allows administration via an XMPP client that supports ad-hoc commands
		--"admin_shell"; -- Allow secure administration via 'prosodyctl shell'
		--"posix"; -- POSIX functionality, sends server to background, enables syslog, etc.
		--"proxy65"; -- Enables a file transfer proxy service which clients behind NAT can use
}

modules_disabled = {
	"offline"; -- Store offline messages
	"s2s"; -- Handle server-to-server connections
}

pidfile = "/tmp/test-prosody.pid";

c2s_ports = { 10444 }

authentication = "internal_hashed"

c2s_require_encryption = false
allow_unencrypted_plain_auth = true

log = {
	debug = "/tmp/test-prosody.log";
	error = "/tmp/test-prosody.err";
}

certificates = "certs"

VirtualHost "localhost"
