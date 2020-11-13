#ifndef ISA_PROJ_ERROREXCEPTIONS_H
#define ISA_PROJ_ERROREXCEPTIONS_H

#include <iostream>
#include <exception>

class DNSException : public std::exception {
protected:
    int code{};
    std::string msg_p{};

public:
    void exit_with_code() noexcept {
        exit(code);
    }
};

class BadArgs_E : public DNSException {
public:
    BadArgs_E() {
        this->code = 1;
        std::cerr << "Incorrect arguments." << std::endl;
    }

    explicit BadArgs_E(std::string msg) {
        this->code = 1;
        std::cerr << msg << std::endl;
    }
};

class ServerErr_E : public DNSException {
public:
    explicit ServerErr_E(std::string msg) {
        this->code = 2;
        std::cerr << msg << std::endl;
    }
};

class DeviceErr_E : public DNSException {
public:
    explicit DeviceErr_E(std::string msg) {
        this->code = 3;
        std::cerr << msg << std::endl;
    }
};

class PcapErr_E : public DNSException {
public:
    explicit PcapErr_E(std::string msg) {
        this->code = 4;
        std::cerr << msg << std::endl;
    }
};

class DomainLoopUp_E : public DNSException {
public:
    explicit DomainLoopUp_E(std::string msg) {
        this->code = 5;
        std::cerr << msg << std::endl;
    }
};

class DNS_Filter_E : public DNSException {

public:
    explicit DNS_Filter_E(std::string msg) {
        this->code = 5;
        std::cerr << msg << std::endl;
    }
};

class ResolvFire_E : public DNSException {

public:
    explicit ResolvFire_E(std::string msg) {
        this->code = 5;
        std::cerr << msg << std::endl;
    }
};


#endif //ISA_PROJ_ERROREXCEPTIONS_H
