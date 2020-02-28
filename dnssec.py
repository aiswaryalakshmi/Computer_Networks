import threading 
import os
import socket
import dns.query
import dns.dnssec
import dns
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

# Check if it is an NSEC response
def check_nsec(response_string):
    nsec3 = " NSEC3 "
    nsec = " NSEC "
    if (nsec in response_string) or (nsec3 in response_string):
        return True
    return False

# Check the status code of response
def check_rcode(response_string):
    rcode = "NOERROR"
    if rcode in response_string:
        return True
    return False

# Get the list of ZSK from response message
def get_DNSKEY_ZSK(server_name, response_string):
    zsk_list = []
    for ass in response_string.split("\n"):
        a_rec = re.search("^"+server_name+"* DNSKEY 256 3 .+$", ass)
        if a_rec != None:
            for stri in a_rec.group().split("\n"):
                zsk_list.append(stri.rsplit(' IN DNSKEY ', 1)[1])
    return zsk_list

# Get the list of KSK from response message
def get_DNSKEY_KSK(server_name, response_string):
    ksk_list = []
    for ass in response_string.split("\n"):
        a_rec = re.search("^"+server_name+"* DNSKEY 257 3 .+$", ass)
        if a_rec != None:
            for stri in a_rec.group().split("\n"):
                ksk_list.append(stri.rsplit(' IN DNSKEY ', 1)[1])
    return ksk_list

# Get the list of RRSIG A from response message
def get_RRSIG_A(server_name, response_string):
    rrsig_ds_list = []
    for ass in response_string.split("\n"):
        a_rec = re.search("^"+server_name+"* IN RRSIG A .+$", ass)
        if a_rec != None:
            for stri in a_rec.group().split("\n"):
                rrsig_ds_list.append(stri.rsplit(' IN RRSIG A ', 1)[1])
    return rrsig_ds_list

# Get the list of RRSIG DS from response message
def get_RRSIG_DS(server_name, response_string):
    rrsig_ds_list = []
    for ass in response_string.split("\n"):
        a_rec = re.search("^"+server_name+"* IN RRSIG DS .+$", ass)
        if a_rec != None:
            for stri in a_rec.group().split("\n"):
                rrsig_ds_list.append(stri.rsplit(' IN RRSIG DS ', 1)[1])
    return rrsig_ds_list

# Get the list of A records from response message
def get_A(server_name, response_string):
    ds_list = []
    for ass in response_string.split("\n"):
        a_rec = re.search("^"+server_name+"* IN A .+$", ass)
        if a_rec != None:
            for stri in a_rec.group().split("\n"):
                ds_list.append(stri.rsplit(' IN A ', 1)[1])
    return ds_list

# Get the list of DS records from response message
def get_DS(server_name, response_string):
    ds_list = []
    for ass in response_string.split("\n"):
        a_rec = re.search("^"+server_name+"* IN DS .+$", ass)
        if a_rec != None:
            for stri in a_rec.group().split("\n"):
                ds_list.append(stri.rsplit(' IN DS ', 1)[1])
    return ds_list

# Get the list of RRSIG DNSKEY from response message
def get_RRSIG_DNSKEY(server_name, response_string):
    rrsig_dnskey_list = []
    for ass in response_string.split("\n"):
        a_rec = re.search("^"+server_name+"* IN RRSIG DNSKEY .+$", ass)
        if a_rec != None:
            for stri in a_rec.group().split("\n"):
                rrsig_dnskey_list.append(stri.rsplit(' IN RRSIG DNSKEY ', 1)[1])
    return rrsig_dnskey_list

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

# Get the sequence number in RRSIG
def get_rrsig_seq_no(server_name, response_string, rec_type):#(prev_qname, str(rxx), 'IN RRSIG'):
    ip = ''
    for ass in response_string.split("\n"):
        a_rec = re.search("^"+server_name+"* "+rec_type+" .+$", ass)
        if a_rec != None:
            for stri in a_rec.group().split("\n"):
                ip = stri.rsplit(' ', 1)[1]
                ip = stri.split()[1]
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
def process_mx(ip_url, ns_list, url_type, prev_qname, DS_list):
    qname = dns.name.from_text(ip_url)
    if url_type == "MX":
        q = dns.message.make_query(qname, dns.rdatatype.MX, want_dnssec=True)     
    else:
        q = dns.message.make_query(qname, dns.rdatatype.A, want_dnssec=True)

    qxx = dns.message.make_query(prev_qname, dns.rdatatype.DNSKEY, want_dnssec=True)
            
    for ns in ns_list:
        r = dns.query.udp(q, ns, timeout=1) 

        rxx = dns.query.tcp(qxx, ns, timeout=1)

        rcode_success = check_rcode(str(r))
        rxxcode_success = check_rcode(str(rxx))
            
        if rcode_success is True and rxxcode_success is True:

            if check_nsec(str(r)) is True:
                    print("DNSSEC not supported")
                    sys.exit(1)
            
             # Get KSK from response
            KSK_list = get_DNSKEY_KSK(prev_qname, str(rxx))

            if KSK_list == []:
                print('DNSSec verification failed')
                sys.exit(1)
                 
            # Verify KSK with DS from parent                 
            if DS_list != []:
                for key in KSK_list:
                    key_in_format = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DNSKEY, key)
                    ds_created = dns.dnssec.make_ds(prev_qname, key_in_format, 'SHA256')
                    flag = 0
                    for ds in DS_list:
                        if dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DS, ds) == ds_created:
                            flag = 1
                            break
                    if flag == 1:
                        break
                   
            # Get ZSK from response
            ZSK_list = get_DNSKEY_ZSK(prev_qname, str(rxx))
            
            # Get RRSIG DNSKEY from response
            RRSIG_DNSKEY_list = get_RRSIG_DNSKEY(prev_qname, str(rxx))

            if (ZSK_list == []) or (RRSIG_DNSKEY_list == []):
                    print("DNSSEC verification failed")
                    sys.exit(1)
            
            rrsig_seq_no = get_rrsig_seq_no(prev_qname, str(rxx), 'IN RRSIG')

            RRSET_DNSKEY = dns.rrset.from_text(prev_qname, rrsig_seq_no, 'IN', 'DNSKEY', *ZSK_list, *KSK_list)
                                
            rrsig_dnskey = dns.rrset.from_text(prev_qname, rrsig_seq_no, 'IN', 'RRSIG', 'DNSKEY '+RRSIG_DNSKEY_list[0])

            keys_dict = {
                    dns.name.from_text(prev_qname): dns.rrset.from_text(
                            prev_qname, rrsig_seq_no, 'IN', 'DNSKEY',
                            *ZSK_list,
                            *KSK_list
                        )
                }
            
            # Validate RRSET against RRSIG for DNSKEY
            res = dns.dnssec.validate(RRSET_DNSKEY, rrsig_dnskey, keys_dict)

            A_list =  get_A(str(qname), str(r))

            RRSIG_A_list = get_RRSIG_A(str(qname), str(r))

            if RRSIG_A_list == []:
                    print('DNSSec verification failed')
                    sys.exit(1)

            rrsig_seq_no = get_rrsig_seq_no(str(qname), str(r), 'IN RRSIG')

            RRSET_A = dns.rrset.from_text(str(qname), rrsig_seq_no, 'IN', 'A', *A_list)

            rrsig_a = dns.rrset.from_text(str(qname), rrsig_seq_no, 'IN', 'RRSIG', 'A '+RRSIG_A_list[0])

            keys_dict = {
                    dns.name.from_text(prev_qname): dns.rrset.from_text(
                            prev_qname, rrsig_seq_no, 'IN', 'DNSKEY',
                            *ZSK_list,
                            *KSK_list
                        )
                }
            
            # Validate RRSET against RRSIG for A records
            res = dns.dnssec.validate(RRSET_A, rrsig_a, keys_dict)

            return str(r), str(rxx)

    return "", ''

# Local DNS function
def local_dns(input_url, url_type):

    if url_type == "CNAME":
        input_url = get_cname(input_url)
        url_type = "A"

    if not input_url.endswith('.'):
        input_url = input_url + '.'
        
    ip_url_list = make_ip_url_list(input_url)
        
    ns_list = get_root_server_list()

    qname = dns.name.from_text('.')
    DS_list = []
    RRSIG_DS_list = []
    for i in ip_url_list:
        if qname != '':
            prev_qname = str(qname)
            
        qname = dns.name.from_text(i)
        if url_type == "A":
            q = dns.message.make_query(qname, dns.rdatatype.A, want_dnssec=True)
        elif url_type == "MX":
            q = dns.message.make_query(qname, dns.rdatatype.MX, want_dnssec=True)
        elif url_type == "NS":
            q = dns.message.make_query(qname, dns.rdatatype.NS, want_dnssec=True)
        else:
            print("Error: User input <Type> is invalid")
            sys.exit(1)

        qxx = dns.message.make_query(prev_qname, dns.rdatatype.DNSKEY, want_dnssec=True)
 
        # Run for all servers in NS list, if the servers do not respond with the correct response       
        for ns in ns_list:
            r = dns.query.udp(q, ns, timeout=1)

            rxx = dns.query.tcp(qxx, ns)
            
            rcode_success = check_rcode(str(r))

            rxxcode_success = check_rcode(str(rxx))
            
            if rcode_success is True and rxxcode_success is True:

                if check_nsec(str(r)) is True:
                    print("DNSSEC not supported")
                    sys.exit(1)

                # Get KSK from response
                KSK_list = get_DNSKEY_KSK(prev_qname, str(rxx))

                if KSK_list == []:
                    print('DNSSec verification failed')
                    sys.exit(1)
                    
                 # Verify KSK with DS from parent
                if DS_list != []:
                    for key in KSK_list:
                        key_in_format = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DNSKEY, key)
                        ds_created = dns.dnssec.make_ds(prev_qname, key_in_format, 'SHA256')
                        flag = 0
                        for ds in DS_list:
                            if dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DS, ds) == ds_created:
                                flag = 1
                                break
                        if flag == 1:
                            break
                        
                # Get ZSK from response
                ZSK_list = get_DNSKEY_ZSK(prev_qname, str(rxx))
                
                # Get RRSIG DNSKEY from response
                RRSIG_DNSKEY_list = get_RRSIG_DNSKEY(prev_qname, str(rxx))

                if (ZSK_list == []) or (RRSIG_DNSKEY_list == []):
                    print("DNSSEC verification failed")
                    sys.exit(1)
                    
                rrsig_seq_no = get_rrsig_seq_no(prev_qname, str(rxx), 'IN RRSIG')

                RRSET_DNSKEY = dns.rrset.from_text(prev_qname, rrsig_seq_no, 'IN', 'DNSKEY', *ZSK_list, *KSK_list)
                                    
                rrsig_dnskey = dns.rrset.from_text(prev_qname, rrsig_seq_no, 'IN', 'RRSIG', 'DNSKEY '+RRSIG_DNSKEY_list[0])

                keys_dict = {
                        dns.name.from_text(prev_qname): dns.rrset.from_text(
                                prev_qname, rrsig_seq_no, 'IN', 'DNSKEY',
                                *ZSK_list,
                                *KSK_list
                            )
                    }
                
                # Validate RRSET against RRSIG for DNSKEY
                res = dns.dnssec.validate(RRSET_DNSKEY, rrsig_dnskey, keys_dict)
                
                # Store the DS record for next iteration
                DS_list =  get_DS(str(qname), str(r))

                RRSIG_DS_list = get_RRSIG_DS(str(qname), str(r))

                if (DS_list == []) or (RRSIG_DS_list == []):
                    print("DNSSEC verification failed")
                    sys.exit(1)

                rrsig_seq_no = get_rrsig_seq_no(str(qname), str(r), 'IN RRSIG')

                RRSET_DS = dns.rrset.from_text(str(qname), rrsig_seq_no, 'IN', 'DS', *DS_list)
                                    
                rrsig_ds = dns.rrset.from_text(str(qname), rrsig_seq_no, 'IN', 'RRSIG', 'DS '+RRSIG_DS_list[0])

                keys_dict = {
                        dns.name.from_text(prev_qname): dns.rrset.from_text(
                                prev_qname, rrsig_seq_no, 'IN', 'DNSKEY',
                                *ZSK_list,
                                *KSK_list
                            )
                    }
                
                # Validate RRSET DS records
                res = dns.dnssec.validate(RRSET_DS, rrsig_ds, keys_dict)
                
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
                                pmx, pmxrxx = process_mx(i, ns_list, url_type, str(qname), DS_list)
                                result = get_record_ip(i, pmx, url_type)
                                if result == "":
                                    # Process CNAME records
                                    result = get_record_ip(i, pmx, "CNAME")
                                    str_r = pmx
                                else:
                                    break
                            else:
                            # If there are no NS to resolve the forthcoming requests, then it is either the last response or a CNAME response
                                result = get_record_ip(i, str_r, url_type)
                                if result == "":
                                    result = get_record_ip(i, str_r, "CNAME")
                                break
                    return result
                else:
                    temp_ns_list = get_ns_list(str(r),i)
                    if temp_ns_list != []:
                        ns_list = temp_ns_list
                break
            else:
                print("ERROR: rcode returned is not NOERROR.")
                sys.exit(1)
            
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
