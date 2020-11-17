/**
 * author: xmusko00
 * email: xmusko00@vutbr.cz
 *
 * file: DNSFilter.h
 */


#ifndef ISA_PROJ_DNSFILTER_H
#define ISA_PROJ_DNSFILTER_H

#include <netdb.h>
#include <string>
#include <vector>


#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstdlib>
#include <netdb.h>

#include "DomainLookup.h"

#define BUFFER_LEN 1024

class DNSFilter {
public:
    explicit DNSFilter(DomainLookup *domain_lookup_m, std::string dns_server_ip, int port, int af);

    static bool is_IPv4(std::string ip);

    static bool is_IPv6(std::string ip);

    static bool domain_to_IP(std::string &str);

    static std::string get_server_IP(std::string, int &);

    static void sigterm_handler(int signum);

    void start();

    ~DNSFilter();

protected:
    DomainLookup *domain_lookup;
    int port;
    std::string dns_server;
    int ip_version;

    static std::vector<int> sock_fds;
    static bool run;

    void start_ipv4();

    void start_ipv6();

    bool still_run();

    bool process_dns_header(unsigned char *dns_start, bool &response);

    bool process_dns_body(unsigned char *dns_body, std::string &domain, int &type, int &class_t);

    void get_response(unsigned char *buffer, int &n);

    void sent_response(unsigned char *buffer, int &buffer_len, sockaddr_in client_addr);

    int retransmit_ipv4(unsigned char *buffer, int &buff_len);

    int retransmit_ipv6(unsigned char *buffer, int &buff_len);

    int retransmit(unsigned char *buffer, int &buff_len);

    void set_dns_refused(unsigned char *buffer, int &buff_len);

    void set_dns_notimplemented(unsigned char *buffer, int &buff_len);

#pragma pack(push, 1)
    typedef struct {
        unsigned short int src_port;
        unsigned short int dst_port;
        unsigned short int len;
        unsigned short int checksum;
    } udp_header_struct;

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

#pragma pack(pop)
};


#endif //ISA_PROJ_DNSFILTER_H
