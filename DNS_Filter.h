//
// Created by awesome on 26.10.20.
//

#ifndef ISA_PROJ_DNS_FILTER_H
#define ISA_PROJ_DNS_FILTER_H

#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string>
#include <netdb.h>
#include <string>
#include <fstream>

#include <netinet/in.h>
#include <arpa/inet.h>
//#include "common.h"

class DNS_Filter {
public:
    explicit DNS_Filter(std::string server_a, int port, std::string filter_file);

    void start();

protected:
    int listening_port;
    std::string server;
    int ip_version;
    std::string filter_file;

    pcap_t *pch_req;
    pcap_t *pch_res;

    void set_server_IP();

    struct addrinfo server_addr_info;

    void set_addr_info(std::string server);

    void start_capturing_responses();

    void start_capturing_requests();

    char err_buf[PCAP_ERRBUF_SIZE];

    pcap_t *get_pcap_handler();

    void set_pcap_filter(pcap_t *handler, bpf_u_int32, bool req);
};


#endif //ISA_PROJ_DNS_FILTER_H
