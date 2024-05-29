####################### the last func belongs to chatgpt
import datetime
from scapy.all import *
#from scapy.layers.dns import DNS, DNSQR
#from scapy.layers.inet import IP, ICMP, UDP, Ether

PORT_NSLOOKUP = 53
DNS_GOOGLE_IP = "8.8.8.8"
CLIENT_PORT = 1123

'''
fullmsg = Ether()/ IP(dst="google.com") / ICMP()
ans = srp1(fullmsg, verbose=0)
print(ans.show())
'''



def nslookup_func (domain):
    '''
    this func gets a domain and by sending it to a dns server returns the ip
    :param domain: the domain
    :return: <str> of the ip. format: "<ip>"
    '''

    # the packet
    dns_req = Ether()/ IP(dst=DNS_GOOGLE_IP) / UDP(sport=CLIENT_PORT, dport=PORT_NSLOOKUP) / DNS(rd=1, qd=DNSQR(qname=domain))
    # send packet
    ans = srp1(dns_req, verbose=0)
    ans = str(ans[DNS])[8:]
    ans = ans.strip('", "')  # remove trailing quotes
    print(ans)
    # return the ip of the domain
    return ans


def ping_func (domain):

    ''' this func gives the results of connection try to a ip

    :param ip_domain: the domain we wish to check connection to
    :return: none
    '''

    ping_req = Ether()/ IP(dst=domain) / ICMP()  # the packet
    all_ms = []  # a list to collect all times every request took

    # try connecting 3 times:
    for i in range(3):
        tstart = datetime.now() # the time before request
        ans = srp1(ping_req, verbose=0, timeout=3)  # send request (with timeout)
        tend = datetime.now()  # the time after request

        #get the sec from the results
        time_lst = str(tend - tstart)
        time_lst = time_lst.split(":")
        sec = time_lst[2]
        sec = float(sec)

        # convert sec to ms:
        ms = sec * 1000
        all_ms.append(ms)  # add the new time to list of times

        if ans is None:  # if we ain't got connection
            print("Request timed out.")
        else:  # if we got connection
            print(f"Replay from {nslookup_func(domain)}  time= {ms}ms")

    # calculate avg of the times
    sum = 0
    for ms in all_ms:
        sum += ms  # sum all times in the lst

    avg = sum/len(all_ms)  # devide them by the amount of times
    print(f"avg time: {avg}ms")



def nslookup_func(domain):
    # Example nslookup function to get the IP address of a domain
    # Replace this with the actual implementation of nslookup_func
    return '142.251.142.206'  # Example IP

def tracet_func(domain):
    print(f"Starting traceroute to {domain}")
    dst_ip = nslookup_func(domain)
    ttl_value = 1

    while ttl_value <= 255:
        ping_req = IP(dst=domain, ttl=ttl_value) / ICMP()  # Construct the packet
        ans = sr1(ping_req, verbose=0, timeout=2)  # Send the packet and wait for response

        if ans:
            if ans.haslayer(ICMP):
                if ans.getlayer(ICMP).type == 11:  # Time Exceeded
                    router_ip = ans.src  # Get the source IP address of the response
                    print(f"{ttl_value}) {router_ip}")
                    ttl_value += 1
                elif ans.getlayer(ICMP).type == 0:  # Echo Reply
                    final_ip = ans.src
                    print(f"{ttl_value}) {final_ip} (Destination reached)")
                    break
            else:
                print(f"{ttl_value}) Unexpected ICMP type")
        else:
            print(f"{ttl_value}) No response received.")
            ttl_value += 1

    print('Traceroute complete.')

# Example usage
domain = "google.com"  # Replace with the desired domain
tracet_func(domain)


'''
def tracet_func(domain):
    print("test 1")
    final_ip = ""
    dst_ip = nslookup_func(domain)
    ttl_value = 1

    while not dst_ip == final_ip and final_ip is not None and ttl_value <= 255:

        ping_req = Ether() / IP(dst=domain, ttl=ttl_value) / ICMP()  # the packet
        ans = srp1(ping_req, verbose=0, timeout=2)
        if ans:
            final_ip = ans.src
            ttl_value += 1
            print(f"{ttl_value}) {final_ip}")
        else:
            print("no response received.")
            final_ip = None

    if dst_ip == final_ip:
        print('Reached destination:', dst_ip)
    else:
        print('Destination not reached.')

'''


def main():
    domain_ = input("enter a domain: ")
    #print(nslookup_func(domain_))
    tracet_func(domain_)
    #ping_func(domain_)


if __name__ == '__main__':
    main()
