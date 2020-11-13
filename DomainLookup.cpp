/**
 * author: xmusko00
 * email: xmusko00@vutbr.cz
 *
 * file: DomainLookup.cpp
 */


#include <iostream>
#include <fstream>

#include "DomainLookup.h"
#include "ErrorExceptions.h"

using namespace std;

/**
 * Inicialization. Method loads domain names from specified file
 * @param file_name: file containing domains
 */
DomainLookup::DomainLookup(const string &file_name) {
    ifstream f_handler;
    f_handler.open(file_name.c_str());

    if (!f_handler.is_open())
        throw DomainLoopUp_E("Can not open filter file " + file_name);

    // load domains without comments (#) and new lines
    string line;
    while (!f_handler.eof()) {
        getline(f_handler, line);
        DomainLookup::trim(line);
        if (!line.empty() and line[0] != '#') {
            this->domains.insert(line);
        }
    }

    f_handler.close();
}

/**
 * Checking if given domain if prohibited.
 * @param domain: given domain
 * @return result
 */
bool DomainLookup::searchDomain(std::string domain) {
    int pos;
    string token;

    // root domains
    if (domain.find('.') == std::string::npos) {
        if (this->domains.count(domain)) {
            return true;
        }
    }

    // other domains
    while ((pos = domain.find('.')) != std::string::npos) {
        if (this->domains.count(domain)) {
            return true;
        }
        domain.substr(0, pos);
        domain.erase(0, pos + 1);
    }
    return false;
}
