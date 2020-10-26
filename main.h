#ifndef ISA_PROJ_MAIN_H
#define ISA_PROJ_MAIN_H

#include <string>

typedef struct{
    std::string server;
    int port = 53;
    std::string filter_file_name;
    bool verbose = false;
} dns_args_struct;

#endif //ISA_PROJ_MAIN_H
