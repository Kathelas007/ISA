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

#include "common.h"

using namespace std;

bool DNS_Filter::inst_set = false;
DNS_Filter *DNS_Filter::instance = nullptr;

DNS_Filter::DNS_Filter(string server_a, int port, string filter_file) {
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


void DNS_Filter::request_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    int et_header_len = 14;
    int ip_header_len;
    int udp_header_len = 8;
    int dns_header_len = 12;

    u_char ip_header_version;
    u_char *ip_header_start;

    udp_header_struct *udp_header;
    dns_header_struct *dns_header;
    u_char *dns_body;

    ip_header_start = (u_char *) (packet + et_header_len + 2);
    ip_header_version = ((*ip_header_start) & 0xF0) >> 4;

    //todo musi souhlasit verze ip
    if (ip_header_version == 4) {
        struct iphdr *ip4_header;
        ip4_header = (struct iphdr *) ip_header_start;
        ip_header_len = ip4_header->ihl * 4;
        in_addr buf{.s_addr =  ip4_header->saddr};
        logg(LOG_DEB) << "src IP: " << inet_ntoa(buf) << endl;
        buf.s_addr = ip4_header->daddr;
        logg(LOG_DEB) << "dst IP: " << inet_ntoa(buf) << endl;

    } else if (ip_header_version == 6) {
        struct ip6_hdr *ip6_header;
        ip6_header = (struct ip6_hdr *) ip_header_start;
        ip_header_len = 40;
        char buff[320];
        inet_ntop(AF_INET6, &(ip6_header->ip6_src), buff, sizeof(ip6_header->ip6_src));
        logg(LOG_DEB) << "src IP: " << buff << endl;
        inet_ntop(AF_INET6, &(ip6_header->ip6_dst), buff, sizeof(ip6_header->ip6_dst));
        logg(LOG_DEB) << "buff IP: " << buff << endl;
    } else {
        logg(LOG_DEB) << "error, wrong ip version: " << ip_header_version << endl;
        return;
    }

    udp_header = (udp_header_struct *) (ip_header_start + ip_header_len);
    udp_header->dst_port = htons(udp_header->dst_port);
    udp_header->src_port = htons(udp_header->src_port);
    udp_header->len = htons(udp_header->len);
    udp_header->checksum = htons(udp_header->checksum);

    logg(LOG_DEB) << "src port: " << udp_header->src_port << endl;
    logg(LOG_DEB) << "dst port: " << udp_header->dst_port << endl;

    dns_header = (dns_header_struct *) (ip_header_start + ip_header_len + udp_header_len);
    dns_header->id = htons(dns_header->id);
    dns_header->q_count = htons(dns_header->q_count);
    dns_header->ans_count = htons(dns_header->ans_count);
    dns_header->auth_count = htons(dns_header->auth_count);
    dns_header->add_count = htons(dns_header->add_count);

    // todo zkontrolovat vic header
    logg(LOG_DEB) << "qc: " << dns_header->q_count << endl;
    logg(LOG_DEB) << "response: " << (int) dns_header->response << endl;

    dns_body = (u_char *) (ip_header_start + ip_header_len + udp_header_len + dns_header_len);

    int octet_id = 0;
    unsigned int len_octet = (unsigned int) *dns_body;
    string question{};
    if (dns_header->response == 0) {
        while (len_octet != 0) {
            question.append((char *) (dns_body + octet_id + 1), len_octet);
            question.append(1, '.');
            octet_id += len_octet + 1;
            len_octet = (u_char) *(dns_body + octet_id);
        }
        question.erase(question.length() - 1, 1);
        logg(LOG_DEB) << "question: " << question << endl << endl;
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

