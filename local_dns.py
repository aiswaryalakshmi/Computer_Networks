import threading 
import os
import socket
import dns.query
from string import ascii_lowercase
import re
import sys
import datetime

# Function to make IP address list from string format
def make_ip_url_list(a):
    iterator = a.count(".")
    ip_url_list = []
    if iterator == 1:
        return [a]
    else:
        iterator -= 1
        while iterator > 0:
            ip_url_list.append(".".join(a.split(".")[iterator:]))
            iterator -= 1
        ip_url_list.append(a)
        return ip_url_list

# Get CNAME from CNAME record
def get_cname(c_record):
    c_rec_cleaned = c_record.split("\n")
    c_name = c_rec_cleaned[0].rsplit(' ', 1)[1]
    return c_name

# Check the status code of response
def check_rcode(response_string):
    rcode = "NOERROR"
    if rcode in response_string:
        return True
    return False

# Get the RRSET of the record types passed
def get_record_ip(server_name, response_string, rec_type):
    ip = ''
    for ass in response_string.split("\n"):
        a_rec = re.search("^"+server_name+"* "+rec_type+" .+$", ass)
        if a_rec != None:
            ip += a_rec.group()
            ip += "\n"
    return ip

# Get IP address of A type record
def get_a_record_ip(server_name, response_string):
    ip = ''
    for ass in response_string.split("\n"):
        a_rec = re.search("^"+server_name+"* A .+$", ass)
        if a_rec != None:
            for stri in a_rec.group().split("\n"):
                ip = stri.rsplit(' ', 1)[1]
            break
    return ip

# Get NS IP address list
def get_ns_list(response_string, parent_domain):
    ns_name_list = []
    for ass in response_string.split("\n"):
        x = re.search("^"+parent_domain+"* NS .+$", ass)
        if x != None:     
            for stri in x.group().split("\n"):
                ns_name_list.append(stri.rsplit(' ', 1)[1])

    ns_list = []
    for server_name in ns_name_list:
        ip = get_a_record_ip(server_name, response_string)
        if ip != "":
            ns_list.append(ip)
            
    if ns_list == [] and ns_name_list != []:
        for server_name in ns_name_list:
        
            # If NS server IP not found, start from root
            a_record = local_dns(server_name, 'A')
            ip = get_a_record_ip(server_name, a_record)
            
            if ip != "":
                ns_list.append(ip)
        if ns_list == []:
            print("ERROR: NS server IP not found.")
            sys.exit(1)              
    return ns_list

# Root server IP
def get_root_server_list():
    return ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13',
            '192.203.230.10', '192.5.5.241', '192.112.36.4', '198.97.190.53',
            '192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42', '202.12.27.33']

# To process the end node records (MX/A)
def process_mx(ip_url, ns_list, url_type):
    qname = dns.name.from_text(ip_url)
    if url_type == "MX":
        q = dns.message.make_query(qname, dns.rdatatype.MX)
    else:
        q = dns.message.make_query(qname, dns.rdatatype.A)

    for ns in ns_list:
        r = dns.query.udp(q, ns, timeout=60)
        rcode_success = check_rcode(str(r))
            
        if rcode_success is True:
            return str(r)

    return ""

# Local DNS function
def local_dns(input_url, url_type):

    if url_type == "CNAME":
        input_url = get_cname(input_url)
        url_type = "A"

    if not input_url.endswith('.'):
        input_url = input_url + '.'
        
    ip_url_list = make_ip_url_list(input_url)
        
    ns_list = get_root_server_list()
    
    for i in ip_url_list:
        qname = dns.name.from_text(i)
        if url_type == "A":
            q = dns.message.make_query(qname, dns.rdatatype.A)
        elif url_type == "MX":
            q = dns.message.make_query(qname, dns.rdatatype.MX)
        elif url_type == "NS":
            q = dns.message.make_query(qname, dns.rdatatype.NS)
        else:
            print("Error: User input <Type> is invalid")
            sys.exit(1)

        # Run for all servers in NS list, if the servers do not respond with the correct response
        for ns in ns_list:
            r = dns.query.udp(q, ns, timeout=60)
            rcode_success = check_rcode(str(r))
            
            if rcode_success is True:
                if i == input_url:
                    str_r = str(r)
                    if url_type == "NS":
                        # If NS records are requested, terminate the program by sending the NS records
                        result = get_record_ip(i, str_r, url_type)
                    else:
                        while True:
                            ns_list = get_ns_list(str_r,i)
                            if ns_list != []:
                                # Process the end server records
                                pmx = process_mx(i, ns_list, url_type)
                                result = get_record_ip(i, pmx, url_type)
                                
                                if result == "":
                                    # Process CNAME records
                                    result = get_record_ip(i, pmx, "CNAME")
                                    if result != "":
                                        print(result)
                                        return local_dns(result, "CNAME")
                                    str_r = pmx
                                else:
                                    break
                            else:
                                # If there are no NS to resolve the forthcoming requests, then it is either the last response or a CNAME response
                                result = get_record_ip(i, str_r, url_type)
                                if result == "":
                                    result = get_record_ip(i, str_r, "CNAME")
                                    if result != "":
                                        print(result)
                                        return local_dns(result, "CNAME")
                                break
                    return result
                else:
                    temp_ns_list = get_ns_list(str(r),i)
                    if temp_ns_list != []:
                        ns_list = temp_ns_list
                break
            
if __name__ == "__main__":

    input_url = sys.argv[1]
    url_type = sys.argv[2]
    start = datetime.datetime.now()
    print("QUESTION SECTION:")
    output = "QUESTION SECTION:"
    print(input_url+". \t IN "+url_type)
    output += input_url+". \t IN "+url_type
    print('')
    print("ANSWER SECTION: ")
    output += "ANSWER SECTION: "
    result = local_dns(input_url, url_type)
    print(result)
    stop = datetime.datetime.now()
    elapsed = stop - start
    print("Query time: "+str(int(elapsed.microseconds)*0.001)+' ms')
    print("WHEN: "+str(datetime.datetime.now()))
    output += "Query time: "+str(int(elapsed.microseconds)*0.001)+' ms'
    output += "WHEN: "+str(datetime.datetime.now())
    print("MSG SIZE rcvd: "+str(sys.getsizeof(output)))
