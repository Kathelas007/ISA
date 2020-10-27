#include <cstring>
#include <utility>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <cstdio>
//#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "DNS_Filter.h"
#include "ErrorExceptions.h"
#include "common.h"

using namespace std;

DNS_Filter::DNS_Filter(string server_a, int port, string filter_file) {
    this->filter_file = std::move(filter_file);
    this->listening_port = port;
    this->server = std::move(server_a);
}

void DNS_Filter::start() {
    this->set_server_IP();
    this->start_capturing_requests();
}

void DNS_Filter::set_server_IP() {
    struct sockaddr_in sa{};

    // if its domain name, convert to IP
    struct hostent *host = gethostbyname(this->server.c_str());
    if (host) {
        log(LOG_DEB) <<"Server host name: " << host->h_name << endl;
        this->server =  inet_ntoa(*(struct in_addr *) host->h_name);
    }

    // its IPv4 address
    if (inet_pton(AF_INET, this->server.c_str(), &(sa.sin_addr)) == 0){
        log(LOG_DEB) <<"Server IP: " << this->server << endl;
        this->ip_version = AF_INET;
        return;
    }

    // its IPv6 address
    if (inet_pton(AF_INET6, this->server.c_str(), &(sa.sin_addr)) == 0){
        log(LOG_DEB) <<"Server IP: " << this->server << endl;
        this->ip_version = AF_INET6;
        return;
    }

    throw ServerErr_E("Not valid server IP address or domain name.");
}

void DNS_Filter::set_addr_info(string server) {
    //http://man7.org/linux/man-pages/man3/getaddrinfo.3.html, first example
    struct addrinfo *results, *res_intem, *res_item;
    struct addrinfo hints_addr{};
    memset(&hints_addr, 0, sizeof(hints_addr));

    hints_addr.ai_family = AF_UNSPEC;
    hints_addr.ai_socktype = SOCK_DGRAM;
    hints_addr.ai_protocol = IPPROTO_DCCP;

    int result = getaddrinfo(server.c_str(), "domain", &hints_addr, &results);

    if (result != 0) {
        throw ServerErr_E("Server error. Maybe bad server argument?");
    }

    int sfd;
    char hostname[30];
    for (res_item = results; res_item != NULL; res_item = res_item->ai_next) {
        sfd = socket(res_item->ai_family, res_item->ai_socktype,
                     res_item->ai_protocol);
        if (sfd == -1)
            continue;

        if (bind(sfd, res_item->ai_addr, res_item->ai_addrlen) == 0)
            cout << "Binded" << endl;

        getnameinfo(res_item->ai_addr, res_item->ai_addrlen, hostname, 30, NULL, 0, 0);
        cout << hostname << endl;
        close(sfd);
    }
}

void DNS_Filter::start_capturing_responses() {
    this->pch_res = get_pcap_handler();
    pcap_close(pch_res);
}

void DNS_Filter::start_capturing_requests() {
    this->pch_req = get_pcap_handler();
    pcap_close(pch_req);
}

pcap_t *DNS_Filter::get_pcap_handler() {
    bpf_u_int32 maskp;
    bpf_u_int32 netp;

    if (pcap_lookupnet(NULL, &netp, &maskp, this->err_buf) != 0) {
        log(LOG_DEB) << "Pcap:" << this->err_buf << endl;
        throw DeviceErr_E("Can not find working interface.");
    }

    pcap_t *handler;
    handler = pcap_open_live(NULL, BUFSIZ, 1, 500, this->err_buf);

    if (handler == nullptr) {
        pcap_close(handler);
        log(LOG_DEB) << "Pcap:" << this->err_buf << endl;
        throw PcapErr_E("Can not get handler.");
    }

    return handler;
}

void DNS_Filter::set_pcap_filter(pcap_t *handler, bpf_u_int32, bool req) {
    //hhttps://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Destination_unreachable
    //https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol_for_IPv6

    string filter_contend;
    bpf_program filter{};

    if(req){

    }

    if (ip_type == AF_INET) {
        filter_contend =
                "icmp[icmptype]==icmp-unreach and icmp[icmpcode]==3 and src " + target_IP;
    } else {
        filter_contend = "icmp6 and ip6[40]==1 and src " + target_IP;
    }


    if (pcap_compile(handler, &filter, filter_contend.c_str(), 0, maskp) != 0) {
        pcap_close(handler);
        string msg = "Function pcap_compile() failed with msg: ";
        msg.append(pcap_geterr(handler));
        exit_scanner(INTERN_ERR, msg);
    }

    if (pcap_setfilter(handler, &filter) != 0) {
        pcap_close(handler);
        exit_scanner(INTERN_ERR, "Function pcap_setfilter() failed.");
    }

}
