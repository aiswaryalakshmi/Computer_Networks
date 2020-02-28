# Local DNS Implementation

## External libraries used:

import dns.query <br>
import dns.dnssec

**NOTE:** The programs have been implemented in Python3.

## How to run the program:

### Part-A:
<pre>
			python local_dns.py &lt;url&gt; &lt;request_type&gt;
	<b>example:</b>	python local_dns.py www.google.com A
</pre>
### Part-B:
<pre>
			python dnssec.py &lt;url&gt; &lt;request_type&gt;
	<b>example:</b>	python dnssec.py verisigninc.com A
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
<pre>
>>> 
 RESTART: C:\Users\Aiswarya\fcn_assignment1\renganathan-aiswarya lakshmi-HW1\local_dns.py 
QUESTION SECTION:
www.google.com. 	 IN A

ANSWER SECTION: 
www.google.com. 300 IN A 172.217.12.132

Query time: 245.445 ms
WHEN: 2019-09-26 22:00:24.280219
MSG SIZE rcvd: 158
</pre>
<pre>
>>> 
 RESTART: C:\Users\Aiswarya\fcn_assignment1\renganathan-aiswarya lakshmi-HW1\local_dns.py 
QUESTION SECTION:
google.com. 	 IN MX

ANSWER SECTION: 
google.com. 600 IN MX 50 alt4.aspmx.l.google.com.
google.com. 600 IN MX 30 alt2.aspmx.l.google.com.
google.com. 600 IN MX 10 aspmx.l.google.com.
google.com. 600 IN MX 40 alt3.aspmx.l.google.com.
google.com. 600 IN MX 20 alt1.aspmx.l.google.com.

Query time: 349.32 ms
WHEN: 2019-09-26 22:00:53.243911
MSG SIZE rcvd: 154
</pre>
<pre>
>>> 
 RESTART: C:\Users\Aiswarya\fcn_assignment1\renganathan-aiswarya lakshmi-HW1\local_dns.py 
QUESTION SECTION:
google.com. 	 IN NS

ANSWER SECTION: 
google.com. 172800 IN NS ns2.google.com.
google.com. 172800 IN NS ns1.google.com.
google.com. 172800 IN NS ns3.google.com.
google.com. 172800 IN NS ns4.google.com.

Query time: 341.093 ms
WHEN: 2019-09-26 22:01:10.914758
MSG SIZE rcvd: 155
</pre>
<pre>
>>> 
 RESTART: C:\Users\Aiswarya\fcn_assignment1\renganathan-aiswarya lakshmi-HW1\local_dns.py 
QUESTION SECTION:
www.amazon.com. 	 IN A

ANSWER SECTION: 
www.amazon.com. 1800 IN CNAME www.cdn.amazon.com.

www.cdn.amazon.com. 60 IN CNAME www.amazon.com.edgekey.net.

www.amazon.com.edgekey.net. 300 IN CNAME e15316.e22.akamaiedge.net.


Query time: 982.828 ms
WHEN: 2019-09-26 22:28:16.954597
MSG SIZE rcvd: 158
</pre>
<pre>
>>> 
 RESTART: C:\Users\Aiswarya\fcn_assignment1\renganathan-aiswarya lakshmi-HW1\dnssec.py 
QUESTION SECTION:
www.google.com. 	 IN A

ANSWER SECTION: 
DNSSEC not supported
</pre>
<pre>
>>> 
 RESTART: C:\Users\Aiswarya\fcn_assignment1\renganathan-aiswarya lakshmi-HW1\dnssec.py 
QUESTION SECTION:
www.dnssec-failed.org. 	 IN A

ANSWER SECTION: 
DNSSEC verification failed
</pre>
<pre>
>>> 
 RESTART: C:\Users\Aiswarya\fcn_assignment1\renganathan-aiswarya lakshmi-HW1\dnssec.py 
QUESTION SECTION:
verisigninc.com. 	 IN A

ANSWER SECTION: 
verisigninc.com. 3600 IN A 72.13.63.55
verisigninc.com. 3600 IN RRSIG A 8 2 3600 20191010185820 20190926185820 30234 verisigninc.com. Bl0iyFHdzYFrdXMN77b4N2Vq949sRens hF0VqEs8d6KznYRtK2lqc59eD/pL3WYg Ek/FkrLL5sh44jDSu17a0kJfC75bO6Br z9EjbtE4I85rrGCItBEeJJaT4F8XiYGk x/2v+gRlVVNP0agC+HpoolmLcCo9YL+j b8FuUYE5Bv8=

Query time: 851.457 ms
WHEN: 2019-09-26 21:34:02.432660
MSG SIZE rcvd: 159
</pre>

## Findings

Generally, the Google DNS server performed the best for all the sites queried. Interestingly, for some of the sites like Sohu.com, Taobao.com, Login.tmall.com, etc. the python DNS yielded better response than the default local DNS server(dig). 
The Response Time of the three DNS are compared as below:

![cdf](/images/cdf.png | width=250)
