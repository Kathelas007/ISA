/**
 * author: xmusko00
 * email: xmusko00@vutbr.cz
 *
 * file: main.cpp
 */

#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include <string>
#include <cstring>

#include "ErrorExceptions.h"
#include "DomainLookup.h"
#include "DNS_Filter.h"

#include "common.h"

using namespace std;

typedef struct {
    std::string server;
    int port = 53;
    std::string filter_file_name;
    bool verbose = false;
} dns_args_struct;

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
    if (args->port < 0 || args->port > 65535)
        throw BadArgs_E("Port must be a number in range <0, 65535>");

}

int main(int argc, char **argv) {
    // TODO verbose mode
    // TODO SERVFAIL 	RCODE:2  Server failed to complete the DNS request
    //
    //

    // parse args
    dns_args_struct args;
    try {
        parse_args(argc, argv, &args);
    }
    catch (BadArgs_E &e) {
        e.exit_with_code();
    }

    if (args.verbose)
        log_level = LOG_VERB;
    else
        log_level = LOG_DIS;

    // prepare dns domain searching
    DomainLookup *domain_lookup;
    try {
        domain_lookup = new DomainLookup(args.filter_file_name);
    }
    catch (DomainLoopUp_E &e) {
        e.exit_with_code();
    }

    // get dns_server IP, IP version, listening IP
    string outer_server_IP;
    int af;
    try {
        outer_server_IP = DNS_Filter::get_server_IP(args.server, af);
    }
    catch (ServerErr_E &e) {
        e.exit_with_code();
    }

    logg(LOG_VERB) << "DNS server IP: " << outer_server_IP << endl;

    // init filter servers
    auto dns_filter = new DNS_Filter(domain_lookup, args.server, args.port, af);

    // set sigkill handler in case of CTRL+C
    signal(SIGINT, DNS_Filter::sigkill_handler);

    dns_filter->start();

    // clean up
    delete dns_filter;
    delete domain_lookup;
    return 0;
}
