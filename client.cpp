// Part of Measurement Kit <https://measurement-kit.github.io/>.
// Measurement Kit is free software under the BSD license. See AUTHORS
// and LICENSE for more information on the copying conditions.

#include "libcareswrap.hpp"

#include <signal.h>
#include <stdlib.h>

#include <iostream>

#include "argh.h"

static void usage() {
  std::clog << "\n";
  std::clog << "Usage: chan [options] <hostname>\n";
  std::clog << "\n";
  std::clog << "  --verbose             : be verbose\n";
  std::clog << std::endl;
}

int main(int, char **argv) {
  using namespace measurement_kit;
  libcareswrap::Channel chan;
  std::string hostname;

  {
    argh::parser cmdline;
    cmdline.parse(argv);
    for (auto &flag : cmdline.flags()) {
      if (flag == "verbose") {
        chan.settings.verbosity = libcareswrap::verbosity_debug;
        std::clog << "will be verbose" << std::endl;
      } else {
        std::clog << "fatal: unrecognized flag: " << flag << std::endl;
        usage();
        exit(EXIT_FAILURE);
      }
    }
    if (cmdline.pos_args().size() != 2) {
      std::clog << "fatal: missing mandatory nostname" << std::endl;
      usage();
      exit(EXIT_FAILURE);
    }
    hostname = cmdline.pos_args()[1];
    std::clog << "will use host: " << hostname << std::endl;
  }

#ifdef _WIN32
  {
    WORD requested = MAKEWORD(2, 2);
    WSADATA data;
    if (::WSAStartup(requested, &data) != 0) {
      std::clog << "fatal: WSAStartup() failed" << std::endl;
      exit(EXIT_FAILURE);
    }
  }
#endif

  // Make sure you initialize ARES before running any query.
  if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS) {
    std::clog << "fatal: cannot initialize ares" << std::endl;
    exit(EXIT_FAILURE);
  }

  libcareswrap::Result result;
  bool rv = chan.resolve(AF_UNSPEC, hostname, &result);
  if (rv) {
    std::clog << "status=" << result.status << " timeouts=" << result.timeouts
              << " canonname=" << result.canonname << std::endl;
    std::clog << "IPv4:" << std::endl;
    for (auto &s : result.inet) {
        std::clog << "- " << s << std::endl;
    }
    std::clog << "IPv6:" << std::endl;
    for (auto &s : result.inet6) {
        std::clog << "- " << s << std::endl;
    }
  }

  return (rv) ? EXIT_SUCCESS : EXIT_FAILURE;
}
