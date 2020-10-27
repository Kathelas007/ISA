#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include <string>
#include <cstring>

#include "ErrorExceptions.h"
#include "DNS_Filter.h"
//#include "common.h"

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
    dns_args_struct args;

    // parse args
    try {
        parse_args(argc, argv, &args);
    }
    catch (DNSException &e) {
        e.exit_with_msg();
    }

    //start filter
//    log(LOG_VERB) << "Starting filter ..." << endl;
    DNS_Filter *dns_filter;
    try {
        dns_filter = new DNS_Filter(args.server, args.port, args.filter_file_name);
        dns_filter->start();
    }
    catch (DNSException &e) {
        delete dns_filter;
    }

    // clean up
    delete dns_filter;
    return 0;
}
