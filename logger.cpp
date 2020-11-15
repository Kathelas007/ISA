/**
 * author: xmusko00
 * email: xmusko00@vutbr.cz
 *
 * file: common.h
 * description: basic logger
 */

#include <string>
#include <ostream>

#include "logger.h"

log_level_t log_level = LOG_DEB;

class mystreambuf : public std::streambuf {
};

mystreambuf no_srtreambuf;
std::ostream no_cout(&no_srtreambuf);
