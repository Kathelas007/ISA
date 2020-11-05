#ifndef ISA_PROJ_ERROREXCEPTIONS_H
#define ISA_PROJ_ERROREXCEPTIONS_H

#include <iostream>
#include <exception>

class DNSException : public std::exception {
protected:
    int code{};
    std::string msg;

public:
    const char *what() noexcept {
        return msg.c_str();
    }

    void exit_with_msg() noexcept {
        std::cerr << msg.c_str() << std::endl;
        exit(code);
    }
};

class BadArgs_E : public DNSException {
public:
    BadArgs_E() {
        this->code = 1;
        this->msg = "Incorrect arguments.";
    }

    explicit BadArgs_E(std::string msg) {
        this->code = 1;
        this->msg = msg;
    }
};

class ServerErr_E : public DNSException {
public:
    explicit ServerErr_E(std::string msg) {
        this->code = 2;
        this->msg = msg;
    }
};

class DeviceErr_E: public DNSException {
public:
    explicit DeviceErr_E(std::string msg) {
        this->code = 3;
        this->msg = msg;
    }
};

class PcapErr_E: public DNSException {
public:
    explicit PcapErr_E(std::string msg) {
        this->code = 4;
        this->msg = msg;
    }
};

class DomainLoopUp_E: public DNSException {
public:
    explicit DomainLoopUp_E(std::string msg) {
        this->code = 5;
        this->msg = msg;
    }
};

class DNS_Filter_E : public DNSException {

public:
    explicit DNS_Filter_E(std::string msg = "Server is singleton.") {
        this->code = 5;
        this->msg = msg;
    }
};

class ResolvFire_E : public DNSException {

public:
    explicit ResolvFire_E(std::string msg = "Server is singleton.") {
        this->code = 5;
        this->msg = msg;
    }
};


#endif //ISA_PROJ_ERROREXCEPTIONS_H
