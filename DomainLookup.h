/**
 * author: xmusko00
 * email: xmusko00@vutbr.cz
 *
 * file: DomainLookup.h
 */

#ifndef ISA_PROJ_DOMAINLOOKUP_H
#define ISA_PROJ_DOMAINLOOKUP_H

#include <vector>
#include <string>
#include <unordered_map>

#include <bits/stdc++.h>

class DomainLookup {
public:
    std::unordered_set<std::string> domains{};

    // trim whitespaces from left
    static inline void ltrim(std::string &s) {
        s.erase(s.begin(), std::find_if(s.begin(), s.end(),
                                        std::not1(std::ptr_fun<int, int>(std::isspace))));
    }

    // trim whitespaces from right
    static inline void rtrim(std::string &s) {
        s.erase(std::find_if(s.rbegin(), s.rend(),
                             std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
    }

    // trim whitespaces from both sides
    static inline void trim(std::string &s) {
        ltrim(s);
        rtrim(s);
    }

    explicit DomainLookup(const std::string &);

    bool searchDomain(std::string);
};


#endif //ISA_PROJ_DOMAINLOOKUP_H
