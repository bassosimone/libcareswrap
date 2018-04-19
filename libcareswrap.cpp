// Part of Measurement Kit <https://measurement-kit.github.io/>.
// Measurement Kit is free software under the BSD license. See AUTHORS
// and LICENSE for more information on the copying conditions.

#ifndef _WIN32
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <unistd.h>
#endif

#include <errno.h>
#include <limits.h>

#include <chrono>
#include <iomanip>
#include <iostream>
#include <sstream>

#include "libcareswrap.hpp"

extern "C" {
using namespace measurement_kit::libcareswrap;

// Utilities

#ifdef _WIN32
#define OS_ERROR_IS_EINTR() (false)
#define OS_SSIZE_MAX INT_MAX
#define OS_EINVAL WSAEINVAL
#define AS_OS_SIZE(x) ((int)x)
#define AS_OS_SOCKLEN(x) ((int)x)
#define AS_OS_SOCKLEN_STAR(x) ((int *)x)
#else
#define OS_ERROR_IS_EINTR() (errno == EINTR)
#define OS_SSIZE_MAX SSIZE_MAX
#define OS_EINVAL EINVAL
#define AS_OS_SIZE(x) ((size_t)x)
#define AS_OS_SOCKLEN(x) ((socklen_t)x)
#define AS_OS_SOCKLEN_STAR(x) ((socklen_t *)x)
#endif

#define EMIT_WARNING(statements)                   \
  do {                                             \
    if (settings.verbosity >= verbosity_warning) { \
      std::stringstream ss;                        \
      ss << statements;                            \
      on_warning(ss.str());                        \
    }                                              \
  } while (0)

#define EMIT_INFO(statements)                   \
  do {                                          \
    if (settings.verbosity >= verbosity_info) { \
      std::stringstream ss;                     \
      ss << statements;                         \
      on_info(ss.str());                        \
    }                                           \
  } while (0)

#define EMIT_DEBUG(statements)                   \
  do {                                           \
    if (settings.verbosity >= verbosity_debug) { \
      std::stringstream ss;                      \
      ss << statements;                          \
      on_debug(ss.str());                        \
    }                                            \
  } while (0)

static bool now() noexcept {
  static std::chrono::time_point<std::chrono::steady_clock> t0;
  std::chrono::duration<double> elapsed = std::chrono::steady_clock::now() - t0;
  return elapsed.count();
}

static void represent_into(const std::string &data,
                           std::stringstream *ss) noexcept {
  assert(ss != nullptr);
  (*ss) << "\"";
  for (size_t i = 0; i < data.size(); ++i) {
    unsigned char ch = data[i];
    (*ss) << std::hex << std::setfill('0') << std::setw(2) << (unsigned int)ch;
    if (i < data.size() - 1) {
      (*ss) << " ";
    }
  }
  (*ss) << "\"";
}

static std::string represent(const std::string &data) noexcept {
  std::stringstream ss;
  represent_into(data, &ss);
  return ss.str();
}

static std::string representv(const std::vector<std::string> &datav) {
  std::stringstream ss;
  ss << "[ ";
  for (auto &data : datav) {
    represent_into(data, &ss);
  }
  ss << " ]";
  return ss.str();
}

// Replacements for ARES socket functions using our Channel. These allows us
// to measure at the socket level (timing, buffers, etc).

static ares_socket_t asocket(int domain, int type, int protocol,
                             void *opaque) noexcept {
  auto channel = static_cast<Channel *>(opaque);
  channel->set_last_error(0);
  auto sock = channel->socket(domain, type, protocol);
  if (sock != -1) {
    if (channel->setnonblocking(sock) != 0) {
      channel->closesocket(sock);
      sock = -1;
      // FALLTHROUGH
    }
  }
  {
    SocketData info;
    info.now = now();
    info.domain = domain;
    info.type = type;
    info.protocol = protocol;
    info.retval = sock;
    info.sys_error = channel->get_last_error();
    channel->on_socket_data(std::move(info));
  }
  return sock;
}

static int aclose(ares_socket_t sock, void *opaque) noexcept {
  auto channel = static_cast<Channel *>(opaque);
  channel->set_last_error(0);
  auto retval = channel->closesocket(sock);
  {
    CloseData info;
    info.now = now();
    info.socket = sock;
    info.sys_error = channel->get_last_error();
    info.retval = retval;
    channel->on_close_data(std::move(info));
  }
  return retval;
}

static int aconnect(ares_socket_t sock, const sockaddr *sa,
                    ares_socklen_t salen, void *opaque) noexcept {
  // TODO(bassosimone): for TCP sockets it may be interesting to know the
  // time-to-connect which we can perhaps measure by making the socket blocking
  // before calling connect() and then making it non-blocking again.
  auto channel = static_cast<Channel *>(opaque);
  channel->set_last_error(0);
  auto retval = channel->connect(sock, sa, salen);
  {
    ConnectData info;
    info.now = now();  // Note: non blocking
    info.socket = sock;
    char address[NI_MAXHOST];
    char port[NI_MAXSERV];
    if (getnameinfo(sa, salen, address, sizeof(address), port, sizeof(port),
                    NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
      info.address = address;
      info.port = port;
    }
    info.retval = retval;
    info.sys_error = channel->get_last_error();
    channel->on_connect_data(std::move(info));
  }
  return retval;
}

static ares_ssize_t arecvfrom(ares_socket_t sock, void *data, size_t count,
                              int flags, sockaddr *sa, ares_socklen_t *salen,
                              void *opaque) noexcept {
  auto channel = static_cast<Channel *>(opaque);
  channel->set_last_error(0);
  auto retval = channel->recvfrom(sock, data, count, flags, sa, salen);
  {
    RecvfromData info;
    info.now = now();  // Note: non blocking
    info.socket = sock;
    info.retval = retval;
    info.sys_error = channel->get_last_error();
    if (retval > 0) {
      info.data = std::string{(char *)data, (size_t)retval};
      char address[NI_MAXHOST];
      char port[NI_MAXSERV];
      if (getnameinfo(sa, *salen, address, sizeof(address), port, sizeof(port),
                      NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
        info.address = address;
        info.port = port;
      }
    }
    channel->on_recvfrom_data(std::move(info));
  }
  return retval;
}

static ares_ssize_t asendv(ares_socket_t sock, const iovec *iov, int iovlen,
                           void *opaque) noexcept {
  auto channel = static_cast<Channel *>(opaque);
  channel->set_last_error(0);
  auto retval = channel->sendv(sock, iov, iovlen);
  {
    SendvData info;
    info.now = now();  // Note: non blocking
    info.socket = sock;
    for (int i = 0; i < iovlen; ++i) {
      auto p = &iov[i];
      if (p->iov_base != nullptr && p->iov_len > 0) {
        info.datav.push_back(std::string{(char *)p->iov_base, p->iov_len});
      }
    }
    info.retval = retval;
    info.sys_error = channel->get_last_error();
    channel->on_sendv_data(std::move(info));
  }
  return retval;
}

// Callback called by ARES. We copy results.

static void acallback(void *opaque, int status, int timeouts,
                      hostent *hent) noexcept {
  auto result = static_cast<Result *>(opaque);
  result->status = status;
  result->timeouts = timeouts;
  if (status != ARES_SUCCESS) {
    return;
  }
  if (hent->h_name != nullptr) {
    result->canonname = hent->h_name;
  }
  char buffer[46];  // See https://stackoverflow.com/a/1076755
  for (auto pp = hent->h_addr_list; *pp != nullptr; ++pp) {
    switch (hent->h_addrtype) {
      case AF_INET: {
        auto p = inet_ntop(hent->h_addrtype, *pp, buffer, sizeof(buffer));
        assert(p != nullptr);
        result->inet.push_back(buffer);
        break;
      }
      case AF_INET6: {
        auto p = inet_ntop(hent->h_addrtype, *pp, buffer, sizeof(buffer));
        assert(p != nullptr);
        result->inet6.push_back(buffer);
        break;
      }
      default:
        assert(false);
    }
  }
}

}  // extern "C"
namespace measurement_kit {
namespace libcareswrap {

// Top-level API

bool Channel::resolve(int family, std::string hostname,
                      Result *result) noexcept {
  switch (family) {
    case AF_UNSPEC:
    case AF_INET:
    case AF_INET6:
      break;
    default:
      EMIT_WARNING("careswrap: invalid family");
      return false;
  }
  if (result == nullptr) {
    EMIT_WARNING("careswrap: null result");
    return false;
  }

  ares_channel chan{};
  {
    ares_options options{};
    options.flags |= ARES_FLAG_NOSEARCH;
    auto optmask = ARES_OPT_FLAGS;
    if (this->ares_init_options(&chan, &options, optmask) != ARES_SUCCESS) {
      EMIT_WARNING("careswrap: ares_init_options() failed");
      return false;
    }
    ares_socket_functions functions{};
    functions.asocket = asocket;
    functions.aclose = aclose;
    functions.aconnect = aconnect;
    functions.arecvfrom = arecvfrom;
    functions.asendv = asendv;
    ares_set_socket_functions(chan, &functions, this);
  }

  if (family == AF_UNSPEC || family == AF_INET6) {
    EMIT_DEBUG("careswrap: resolve AAAA");
    ares_gethostbyname(chan, hostname.c_str(), AF_INET6, acallback, result);
  }
  if (family == AF_UNSPEC || family == AF_INET) {
    EMIT_DEBUG("careswrap: resolve A");
    ares_gethostbyname(chan, hostname.c_str(), AF_INET, acallback, result);
  }

  for (;;) {
    fd_set readset, writeset;
    FD_ZERO(&readset);
    FD_ZERO(&writeset);
    int nfds = this->ares_fds(chan, &readset, &writeset);
    if (nfds <= 0) {
      EMIT_DEBUG("careswrap: no more fds to monitor");
      break;
    }
    timeval tv{}, *tvp = this->ares_timeout(chan, nullptr, &tv);
    int retval = this->select(nfds, &readset, &writeset, nullptr, tvp);
    if (retval < 0 && OS_ERROR_IS_EINTR()) {
      EMIT_DEBUG("careswrap: select() interrupted by signal");
      continue;
    } else if (retval < 0) {
      EMIT_WARNING("careswrap: select() failed: " << this->get_last_error());
      break;
    }
    // Note: we want to invoke invoking ares_process() also on timeout
    ares_process(chan, &readset, &writeset);
  }
  ares_destroy(chan);
  return true;
}

void Channel::on_warning(const std::string &msg) noexcept {
  std::clog << "[!] " << msg << std::endl;
}

void Channel::on_info(const std::string &msg) noexcept {
  std::clog << msg << std::endl;
}

void Channel::on_debug(const std::string &msg) noexcept {
  std::clog << "[D] " << msg << std::endl;
}

void Channel::on_socket_data(SocketData info) noexcept {
  std::clog << "careswrap: socket(): now=" << info.now
            << " domain=" << info.domain << " type=" << info.type
            << " protocol=" << info.protocol << " retval=" << info.retval
            << " sys_error=" << info.sys_error << std::endl;
}

void Channel::on_connect_data(ConnectData info) noexcept {
  std::clog << "careswrap: connect(): now=" << info.now
            << " socket=" << info.socket << " address=" << info.address
            << " port=" << info.port << " retval=" << info.retval
            << " sys_error=" << info.sys_error << std::endl;
}

void Channel::on_recvfrom_data(RecvfromData info) noexcept {
  std::clog << "careswrap: recvfrom(): now=" << info.now
            << " socket=" << info.socket << " data=" << represent(info.data)
            << " retval=" << info.retval << " sys_error=" << info.sys_error
            << std::endl;
}

void Channel::on_sendv_data(SendvData info) noexcept {
  std::clog << "careswrap: sendv(): now=" << info.now
            << " socket=" << info.socket << " datav=" << representv(info.datav)
            << " retval=" << info.retval << " sys_error=" << info.sys_error
            << std::endl;
}

void Channel::on_close_data(CloseData info) noexcept {
  std::clog << "careswrap: close(): now=" << info.now
            << " socket=" << info.socket << " retval=" << info.retval
            << " sys_error=" << info.sys_error << std::endl;
}

// Dependencies

void Channel::set_last_error(int err) noexcept {
#ifdef _WIN32
  ::SetLastError(err);
#else
  errno = err;
#endif
}

int Channel::get_last_error() noexcept {
#ifdef _WIN32
  return ::GetLastError();
#else
  return errno;
#endif
}

Socket Channel::socket(int domain, int type, int protocol) noexcept {
  return ::socket(domain, type, protocol);
}

int Channel::setnonblocking(Socket sock) noexcept {
#ifdef _WIN32
  unsigned long enable = 1;
  if (::ioctlsocket(sock, FIONBIO, &enable) != 0) {
    return -1;
  }
#else
  auto flags = ::fcntl(sock, F_GETFL, 0);
  if (flags < 0) {
    return -1;
  }
  flags |= O_NONBLOCK;
  if (::fcntl(sock, F_SETFL, flags) != 0) {
    return -1;
  }
#endif
  return 0;
}

int Channel::closesocket(Socket sock) noexcept {
#ifdef _WIN32
  return ::closesocket(sock);
#else
  return ::close(sock);
#endif
}

int Channel::connect(Socket sock, const sockaddr *sa, SockLen salen) noexcept {
  return ::connect(sock, sa, AS_OS_SOCKLEN(salen));
}

Ssize Channel::recvfrom(Socket sock, void *base, Size count, int flags,
                        sockaddr *sa, SockLen *salen) noexcept {
  if (count > OS_SSIZE_MAX) {
    this->set_last_error(OS_EINVAL);
    return -1;
  }
  return ::recvfrom(sock, base, AS_OS_SIZE(count), flags, sa,
                    AS_OS_SOCKLEN_STAR(salen));
}

Ssize Channel::sendv(Socket sock, const iovec *iov, int iovcnt) noexcept {
#ifdef _WIN32
  if (iov == nullptr || iovcnt < 0) {
    SetLastError(WSAEINVAL);
    return -1;
  }
  if (iovcnt == 0) {
    return 0;
  }
  constexpr size_t maxiov = 16;
  WSABUF bufs[maxiov];
  iovcnt = (std::min)(iovcnt, maxiov);
  int total = 0;
  for (auto i = 0; i < iovcnt; ++i) {
    bufs[i].buf = (char *)iov[i].iov_base;
    if (iov[i].iov_len > INT_MAX) {
      SetLastError(WSAEINVAL);
      return -1;
    }
    if (total > INT_MAX - iov[i].iov_len) {
      SetLastError(WSAEINVAL);
      return -1;
    }
    bufs[i].len = (unsigned long)iov[i].iov_len;
    total += (int)iov[i].iov_len;
  }
  DWORD nsent = 0;
  if (::WSASend(sock, bufs, (DWORD)iovcnt, &nsent, 0, nullptr, nullptr) != 0) {
    return -1;
  }
  static_cast(sizeof(Ssize) == sizeof(int), "Unexpected Ssize length");
  return (Ssize)nsent;
#else
  return ::writev(sock, iov, iovcnt);
#endif
}

int Channel::select(int maxfd, fd_set *readset, fd_set *writeset,
                    fd_set *exceptset, timeval *tv) noexcept {
  return ::select(maxfd, readset, writeset, exceptset, tv);
}

int Channel::ares_init_options(ares_channel *channelptr, ares_options *options,
                               int optmask) noexcept {
  return ::ares_init_options(channelptr, options, optmask);
}

int Channel::ares_fds(ares_channel channel, fd_set *read_fds,
                      fd_set *write_fds) noexcept {
  return ::ares_fds(channel, read_fds, write_fds);
}

timeval *Channel::ares_timeout(ares_channel channel, timeval *maxtv,
                               timeval *tv) noexcept {
  return ::ares_timeout(channel, maxtv, tv);
}

// Constructor and destructor

Channel::Channel() noexcept {}

Channel::~Channel() noexcept {}

}  // namespace libcareswrap
}  // namespace measurement_kit
