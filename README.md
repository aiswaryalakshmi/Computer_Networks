# Local DNS Implementation

## External libraries used:

import dns.query <br>
import dns.dnssec

**NOTE:** The programs have been implemented in Python3.

## How to run the program:

### Part-A:
<pre>
			python partA.py &lt;url&gt; &lt;request_type&gt;
	<b>example:</b>	python partA.py www.google.com A
</pre>
### Part-B:
<pre>
			python partB.py &lt;url&gt; &lt;request_type&gt;
	<b>example:</b>	python partB.py verisigninc.com A
</pre>

## PART – B DNSSEC Implementation Explanation

For implementing DNSSEC, the code developed for PART-A has been enhanced as follows: <br>
1.	The Name Servers have been requested to provide DNSKEY associated with them.
2.	They are also requested to give the DS records of their child nodes and the RRSIG records.
3.	The DNSKEY (KSK) of the current server is matched with the DS from the parent server. When both are matched, the trust is established, and we proceed further.
4.	All the RRSET records (A, MX, NS, DS, DNSKEY) are validated against their corresponding RRSIG records with the help of the DNSKEYS (ZSK & KSK).
5.	Once the records are validated, we proceed further to parse the records to find the IP of the relevant servers.
6.	Servers in which DNSSEC are not implemented send us back NSEC/NSEC3 records as response for our queries. The error message “DNSSEC not supported” is thrown for such servers and the process is stopped.

## EXPECTED OUTPUT:
>>> 
 RESTART: C:\Users\Aiswarya\fcn_assignment1\renganathan-aiswarya lakshmi-HW1\partB.py 
QUESTION SECTION:
www.google.com. 	 IN A

ANSWER SECTION: 
DNSSEC not supported
>>> 
 RESTART: C:\Users\Aiswarya\fcn_assignment1\renganathan-aiswarya lakshmi-HW1\partB.py 
QUESTION SECTION:
www.dnssec-failed.org. 	 IN A

ANSWER SECTION: 
DNSSEC verification failed
>>> 
 RESTART: C:\Users\Aiswarya\fcn_assignment1\renganathan-aiswarya lakshmi-HW1\partB.py 
QUESTION SECTION:
verisigninc.com. 	 IN A

ANSWER SECTION: 
verisigninc.com. 3600 IN A 72.13.63.55
verisigninc.com. 3600 IN RRSIG A 8 2 3600 20191010185820 20190926185820 30234 verisigninc.com. Bl0iyFHdzYFrdXMN77b4N2Vq949sRens hF0VqEs8d6KznYRtK2lqc59eD/pL3WYg Ek/FkrLL5sh44jDSu17a0kJfC75bO6Br z9EjbtE4I85rrGCItBEeJJaT4F8XiYGk x/2v+gRlVVNP0agC+HpoolmLcCo9YL+j b8FuUYE5Bv8=

Query time: 851.457 ms
WHEN: 2019-09-26 21:34:02.432660
MSG SIZE rcvd: 159
