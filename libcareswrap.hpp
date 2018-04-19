// Part of Measurement Kit <https://measurement-kit.github.io/>.
// Measurement Kit is free software under the BSD license. See AUTHORS
// and LICENSE for more information on the copying conditions.
#ifndef MEASUREMENT_KIT_LIBCARESWRAP_LIBCARESWRAP_HPP
#define MEASUREMENT_KIT_LIBCARESWRAP_LIBCARESWRAP_HPP

#ifndef _WIN32
#include <netdb.h>
#include <sys/select.h>
#include <sys/socket.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include <stdint.h>

#include <string>
#include <vector>

#include <ares.h>

namespace measurement_kit {
namespace libcareswrap {

constexpr uint64_t api_major = 0;
constexpr uint64_t api_minor = 0;
constexpr uint64_t api_patch = 0;

#ifdef _WIN32
using Socket = SOCKET;
using Size = int;
using Ssize = int;
using SockLen = int;
#else
using Socket = int;
using Size = size_t;
using Ssize = ssize_t;
using SockLen = socklen_t;
#endif

class SocketData {
 public:
  double now = 0.0;
  int domain = 0;
  int type = 0;
  int protocol = 0;
  Socket retval = -1;
  int sys_error = 0;
};

class ConnectData {
 public:
  double now = 0.0;
  Socket socket = -1;
  std::string address;
  std::string port;
  int retval = -1;
  int sys_error = 0;
};

class RecvfromData {
 public:
  double now = 0.0;
  Socket socket = -1;
  std::string data;
  Ssize retval = -1;
  std::string address;
  std::string port;
  int sys_error = 0;
};

class SendvData {
 public:
  double now = 0.0;
  Socket socket = -1;
  std::vector<std::string> datav;
  Ssize retval = -1;
  int sys_error = 0;
};

class CloseData {
 public:
  double now = 0.0;
  Socket socket = -1;
  int retval = -1;
  int sys_error = 0;
};

class Result {
 public:
  std::string canonname;
  std::vector<std::string> inet;
  std::vector<std::string> inet6;
  int status = 0;
  int timeouts = 0;
};

constexpr uint64_t verbosity_quiet = 0;
constexpr uint64_t verbosity_warning = 1;
constexpr uint64_t verbosity_info = 2;
constexpr uint64_t verbosity_debug = 3;

class Settings {
 public:
  uint64_t verbosity = verbosity_info;
};

class Channel {
 public:
  // Top-level API

  Settings settings;

  bool resolve(int family, std::string hostname, Result *result) noexcept;

  virtual void on_warning(const std::string &s) noexcept;

  virtual void on_info(const std::string &s) noexcept;

  virtual void on_debug(const std::string &s) noexcept;

  virtual void on_socket_data(SocketData data) noexcept;

  virtual void on_connect_data(ConnectData data) noexcept;

  virtual void on_recvfrom_data(RecvfromData data) noexcept;

  virtual void on_sendv_data(SendvData data) noexcept;

  virtual void on_close_data(CloseData data) noexcept;

  // Dependencies

  virtual void set_last_error(int err) noexcept;

  virtual int get_last_error() noexcept;

  virtual Socket socket(int domain, int type, int protocol) noexcept;

  virtual int setnonblocking(Socket sock) noexcept;

  virtual int closesocket(Socket sock) noexcept;

  virtual int connect(Socket sock, const sockaddr *sa, SockLen salen) noexcept;

  virtual Ssize recvfrom(Socket sock, void *base, Size count, int flags,
                         sockaddr *sa, SockLen *salen) noexcept;

  virtual Ssize sendv(Socket sock, const iovec *iov, int iovcnt) noexcept;

  virtual int select(int, fd_set *, fd_set *, fd_set *, timeval *) noexcept;

  virtual int ares_init_options(ares_channel *channelptr, ares_options *options,
                                int optmask) noexcept;

  virtual int ares_fds(ares_channel channel, fd_set *read_fds,
                       fd_set *write_fds) noexcept;

  virtual timeval *ares_timeout(ares_channel channel, timeval *maxtv,
                                timeval *tv) noexcept;

  // Constructor and destructor

  Channel() noexcept;

  ~Channel() noexcept;
};

}  // namespace libcareswrap
}  // namespace measurement_kit
#endif
