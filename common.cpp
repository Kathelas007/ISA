#include <cstdlib>
#include <string>
#include <ostream>

#include "common.h"

log_level_t log_level = LOG_DEB;

class mystreambuf : public std::streambuf {
};

mystreambuf no_srtreambuf;
std::ostream no_cout(&no_srtreambuf);
