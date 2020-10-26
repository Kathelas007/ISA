#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include <string>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <cstring>

#include "ErrorExceptions.h"
#include "main.h"

using namespace std;

void print_help() {
    cout << "help" << endl;
    exit(0);
}

/**
 * Function checks and parses input arguments. Result is saved into args structure.
 * @param argc number of args
 * @param argv arg values
 * @param parsed args
 */
void parse_args(int argc, char **argv, dns_args_struct *args) {
    int opt;

    string port_str;
    size_t idx_stoi;

    //getting opts
    while ((opt = getopt(argc, argv, "s:p:f:")) != -1) {
        switch (opt) {
            case 's':
                args->server = optarg;
                break;
            case 'p':
                port_str = optarg;
                args->port = stoi(optarg, &idx_stoi);
                break;
            case 'f':
                args->filter_file_name = optarg;
                break;
            case 'h':
                print_help();
                break;
            case 'v':
                args->verbose = true;
                break;
            case '?':
                cerr << "Ignoring unknown option: '" << char(optopt) << "'!" << endl;
                break;
        }
    }

    // check mandatory opts
    if (args->server.empty())
        throw BadArgs_E("Server argument required");
    if (args->filter_file_name.empty())
        throw BadArgs_E("Filter file argument required.");

    //check proper port format
    if (idx_stoi != port_str.length())
        throw BadArgs_E("Port must be a number.");
    if(args->port< 0 || args->port > 65535)
        throw BadArgs_E("Port must be a number in range <0, 65535>");

}

void set_addr_info(string &server, struct addrinfo *result_addr) {
    //http://man7.org/linux/man-pages/man3/getaddrinfo.3.html, first example
    struct addrinfo hints_addr{};
    memset(&hints_addr, 0, sizeof(hints_addr));

    hints_addr.ai_family = AF_UNSPEC;
    hints_addr.ai_socktype = SOCK_DGRAM;

    int result = getaddrinfo(server.c_str(), "domain", &hints_addr, &result_addr);

    if (result != 0) {
        throw ServerErr_E("Server error. Maybe bad server argument?");
    }

}

int main(int argc, char **argv) {
    dns_args_struct args;
    addrinfo serverinfo{};

    try {
        parse_args(argc, argv, &args);
        set_addr_info(args.server, &serverinfo);
    }
    catch (DNSException &e) {
        e.exit_with_msg();
    }

    //start capturing

    return 0;
}
