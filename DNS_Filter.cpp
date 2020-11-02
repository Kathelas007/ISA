#include <cstring>
#include <utility>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <cstdio>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <thread>

#include <cstring>

#include <csignal>
#include <bitset>

#include<netinet/ip.h>
#include<netinet/ip6.h>

#include <cstdio>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <cstring>
#include <unistd.h>

#include "DNS_Filter.h"
#include "ErrorExceptions.h"
#include "DomainLookup.h"

#include "common.h"

using namespace std;

bool DNS_Filter::inst_set = false;
DNS_Filter *DNS_Filter::instance = nullptr;

DNS_Filter::DNS_Filter(DomainLookup *domain_lookup_m, string server_a, int port, string filter_file) {
    this->domain_lookup = domain_lookup_m;
    this->filter_file = std::move(filter_file);
    this->listening_port = port;
    this->server = std::move(server_a);
}

void DNS_Filter::start() {
    if (DNS_Filter::inst_set) {
        throw DNS_Filter_E();
    }
    DNS_Filter::inst_set = true;
    DNS_Filter::instance = this;

    this->set_server_IP();
    this->handler_pcap = get_pcap_handler();

    signal(SIGINT, DNS_Filter::sigkill_handler);

    pcap_loop(this->handler_pcap, 0, request_callback, reinterpret_cast<u_char *>(this));
    pcap_close(handler_pcap);
}

bool DNS_Filter::process_ip(u_char *ip_start, int &length) {
    char ip_header_version = ((*ip_start) & 0xF0) >> 4;

    //todo musi souhlasit verze ip
    if (ip_header_version == 4) {
        struct iphdr *ip4_header;
        ip4_header = (struct iphdr *) ip_start;
        length = ip4_header->ihl * 4;
        in_addr buf{.s_addr =  ip4_header->saddr};
        logg(LOG_DEB) << "src IP: " << inet_ntoa(buf) << endl;
        buf.s_addr = ip4_header->daddr;
        logg(LOG_DEB) << "dst IP: " << inet_ntoa(buf) << endl;
        return true;

    } else if (ip_header_version == 6) {
        struct ip6_hdr *ip6_header;
        ip6_header = (struct ip6_hdr *) ip_start;
        length = 40;
        char buff[320];
        inet_ntop(AF_INET6, &(ip6_header->ip6_src), buff, sizeof(ip6_header->ip6_src));
        logg(LOG_DEB) << "src IP: " << buff << endl;
        inet_ntop(AF_INET6, &(ip6_header->ip6_dst), buff, sizeof(ip6_header->ip6_dst));
        logg(LOG_DEB) << "buff IP: " << buff << endl;
        return true;
    } else {
        // todo error
        logg(LOG_DEB) << "error, wrong ip version: " << ip_header_version << endl;
        return false;
    }
}

bool DNS_Filter::process_udp(u_char *udp_start, int &dst_port) {
    udp_header_struct *udp_header;

    udp_header = (udp_header_struct *) (udp_start);
    udp_header->dst_port = htons(udp_header->dst_port);
    udp_header->src_port = htons(udp_header->src_port);
//    udp_header->len = htons(udp_header->len);
//    udp_header->checksum = htons(udp_header->checksum);

    logg(LOG_DEB) << "src port: " << udp_header->src_port << endl;
    logg(LOG_DEB) << "dst_port port: " << udp_header->dst_port << endl;

    dst_port = udp_header->dst_port;
    return true;
}

bool DNS_Filter::process_dns_header(u_char *dns_start, bool &response) {
    // todo zkontrolovat vic header

    dns_header_struct *dns_header;

    dns_header = (dns_header_struct *) (dns_start);
    dns_header->id = htons(dns_header->id);
    dns_header->q_count = htons(dns_header->q_count);
//    dns_header->ans_count = htons(dns_header->ans_count);
//    dns_header->auth_count = htons(dns_header->auth_count);
//    dns_header->add_count = htons(dns_header->add_count);

    response = dns_header->response;

    logg(LOG_DEB) << "qc: " << dns_header->q_count << endl;
    logg(LOG_DEB) << "response: " << (int) dns_header->response << endl;

    return dns_header->q_count != 1;
}

bool DNS_Filter::process_dns_body(u_char *dns_body, std::string &domain, int &type, int &class_t) {
    int octet_id = 0;
    auto len_octet = (unsigned int) *dns_body;

    while (len_octet != 0) {
        domain.append((char *) (dns_body + octet_id + 1), len_octet);
        domain.append(1, '.');
        octet_id += len_octet + 1;
        len_octet = (u_char) *(dns_body + octet_id);
    }
    domain.erase(domain.length() - 1, 1);

    unsigned short type_us = *(dns_body + octet_id + 1);
    unsigned short class_us = *(dns_body + octet_id + 2);

    type = type_us;
    class_t = class_us;

    logg(LOG_DEB) << "domain: " << domain << endl;
    logg(LOG_DEB) << "type: " << type << endl << "class: " << class_t << endl;

    if (domain.length() <= 0)
        return false;

    return true;
}

void DNS_Filter::request_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    logg(LOG_DEB) << endl;

    DNS_Filter *this_pointer = DNS_Filter::instance;

    int et_header_len = 14;
    int ip_header_len;
    int udp_header_len = 8;
    int dns_header_len = 12;

    u_char *ip_header_start;
    ip_header_start = (u_char *) (packet + et_header_len + 2);
    if (!this_pointer->process_ip(ip_header_start, ip_header_len)) {
        // error
        // ignore
    }

    int dst_port{};
    this_pointer->process_udp(ip_header_start + ip_header_len, dst_port);

    bool response = false;
    u_char *dns_header_start = ip_header_start + ip_header_len + udp_header_len;
    if (!this_pointer->process_dns_header(dns_header_start, response)) {
        if (response) {
            // restransmit
        } else {
            // thats baaaad
        }
    }

    int type, class_t;
    string domain;
    u_char *dns_body;
    dns_body = dns_header_start + dns_header_len;
    if (this_pointer->process_dns_body(dns_body, domain, type, class_t)) {
        if (type == 1 and class_t == 1) {
            // something baad
        } else {
            // retransmit or error
        }
    }

    if(this_pointer->domain_lookup->searchDomain(domain)){
        // do dot send
        // send back info
    } else{
        // retransmit to dns server
    }

}


void DNS_Filter::set_server_IP() {
    unsigned char buf[sizeof(struct in6_addr)];

    // its IPv4 address
    if (inet_pton(AF_INET, this->server.c_str(), buf) == 1) {
        logg(LOG_DEB) << "Server IPv4: " << this->server << endl;
        this->ip_version = AF_INET;
        return;
    }

    // its IPv6 address
    if (inet_pton(AF_INET6, this->server.c_str(), buf) == 1) {
        logg(LOG_DEB) << "Server IPv6: " << this->server << endl;
        this->ip_version = AF_INET6;
        return;
    }

    // if its domain name, convert to IP
    struct hostent *host = gethostbyname(this->server.c_str());
    if (host) {
        logg(LOG_DEB) << "Server host name: " << host->h_name << endl;
        this->server = inet_ntoa(*(struct in_addr *) host->h_name);
    }

    // its IPv4 address
    if (inet_pton(AF_INET, this->server.c_str(), buf) == 1) {
        logg(LOG_DEB) << "Server IP: " << this->server << endl;
        this->ip_version = AF_INET;
        return;
    }

    // its IPv6 address
    if (inet_pton(AF_INET6, this->server.c_str(), buf) == 1) {
        logg(LOG_DEB) << "Server IP: " << this->server << endl;
        this->ip_version = AF_INET6;
        return;
    }

    throw ServerErr_E("Not valid server IP address or domain name.");
}

void DNS_Filter::start_capturing_requests() {

}

void DNS_Filter::start_capturing_responses() {

}

pcap_t *DNS_Filter::get_pcap_handler() {
    bpf_u_int32 maskp;
    bpf_u_int32 netp;

    // check interface
    if (pcap_lookupnet(NULL, &netp, &maskp, this->err_buf) != 0) {
        logg(LOG_DEB) << "Pcap:" << this->err_buf << endl;
        throw DeviceErr_E("Can not find working interface.");
    }

    // get handler
    pcap_t *handler;
    handler = pcap_open_live(NULL, BUFSIZ, 0, 2000, this->err_buf);

    if (handler == nullptr) {
        logg(LOG_DEB) << "Pcap:" << this->err_buf << endl;
        throw PcapErr_E("Can not get handler.");
    }

    // set processing of handling packages as non-blocking
    pcap_setnonblock(handler, 1, err_buf);

    // set filter
    this->set_pcap_filter(handler, maskp);

    return handler;
}

void DNS_Filter::set_pcap_filter(pcap_t *handler, bpf_u_int32 maskp) const {
    string filter_contend;
    bpf_program filter{};

    // set ip version
    if (this->ip_version == AF_INET)
        filter_contend = "ip";
    else
        filter_contend = "ip6";

    // set udp          ip && udp dst port 53
    filter_contend += " && udp dst port " + to_string(this->listening_port);

    // setting and compiling filter
    if (pcap_compile(handler, &filter, filter_contend.c_str(), 0, maskp) != 0) {
        pcap_close(handler);
        logg(LOG_DEB) << "Pcap compile: " << pcap_geterr(handler) << endl;
        throw PcapErr_E("Can not compile filter.");
    }

    if (pcap_setfilter(handler, &filter) != 0) {
        pcap_close(handler);
        logg(LOG_DEB) << "Pcap filter: " << pcap_geterr(handler) << endl;
        throw PcapErr_E("Can not set filter.");
    }

    logg(LOG_DEB) << "Pcap: set filter '" << filter_contend.c_str() << "' " << pcap_geterr(handler) << endl;

}

void DNS_Filter::sigkill_handler(int signum) {
    logg(LOG_VERB) << "Quiting ..." << endl;
    pcap_breakloop(DNS_Filter::instance->handler_pcap);
}






