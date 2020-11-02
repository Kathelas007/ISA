//
// Created by root on 02.11.20.
//

#include <iostream>
#include <fstream>

#include "DomainLookup.h"
#include "ErrorExceptions.h"

using namespace std;

DomainLookup::DomainLookup(const string &file_name) {
    ifstream f_handler;
    f_handler.open(file_name.c_str());

    if (!f_handler.is_open())
        throw DomainLoopUp_E("Can not open filter file " + file_name);

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
