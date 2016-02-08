This is a recursive DNS resolver implemented using C. 
The resolver takes a DNS request as a parameter and performs the DNS resolution recursively querying from root server to TLDs to authoritative server. The server performs previous queries caching to boost the performance.

Run the DNS resolver using the following command:
dns.sh -p PORTNUM

Then test/use the DNS resolver using command: 
dig @localhost -p PORTNUM $QUERY
