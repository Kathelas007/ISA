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

#include <vector>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "DomainLookup.h"

class DNS_Filter {
public:
    explicit DNS_Filter(DomainLookup *domain_lookup_m, std::string server_a, int port, std::string filter_file);

    void start();

protected:
    DomainLookup *domain_lookup;
    int listening_port;
    std::string server;
    int ip_version;
    std::string filter_file;

    pcap_t *handler_pcap;
    pcap_t *pch_res;

    static DNS_Filter *instance;
    static bool inst_set;

    void set_server_IP();

    void start_capturing_responses();

    void start_capturing_requests();

    char err_buf[PCAP_ERRBUF_SIZE];

    pcap_t *get_pcap_handler();

    void set_pcap_filter(pcap_t *, bpf_u_int32) const;

    static void request_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

    static void sigkill_handler(int signum);
};


#pragma pack(push, 1)
typedef struct {
    unsigned short int src_port;
    unsigned short int dst_port;
    unsigned short int len;
    unsigned short int checksum;
} udp_header_struct;

#pragma pack(push, 1)
typedef struct {
    unsigned short id; // identification number

# if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    unsigned char recursion_desired: 1;
    unsigned char truncation: 1;
    unsigned char authoritative_answer: 1;
    unsigned char opcode: 4; // opcode standart == 0
    unsigned char response: 1; // query == 0 or sersponse

    unsigned char reply_code: 4;
    unsigned char reserved: 3;
    unsigned char recursion_available: 1;
# else
    unsigned char response: 1; // query == 0 or sersponse
    unsigned char opcode: 4; // opcode standart == 0
    unsigned char authoritative_answer: 1;
    unsigned char truncation: 1;
    unsigned char recursion_desired: 1;

    unsigned char recursion_available: 1;
    unsigned char reserved: 3;
    unsigned char reply_code: 4;
#endif
    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
} dns_header_struct;


#endif //ISA_PROJ_DNS_FILTER_H
