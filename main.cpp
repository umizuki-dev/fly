/*
 * fly - Minimalist VPNGate Client
 * Copyright (C) 2026
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <arpa/inet.h>
#include <curl/curl.h>
#include <fcntl.h>
#include <getopt.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>  // NOLINT
#include <cstdlib>
#include <fstream>
#include <future>  // NOLINT
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

constexpr char kVersion[] = "1.0.0";
constexpr char kLogPath[] = "/tmp/fly.log";

struct Config {
  std::string country = "JP";
  std::string proto = "udp";
  bool auto_connect = false;
  int count = 10;
  bool verbose = false;
};

struct VpnServer {
  std::string host_name, ip, proto, config_base64;
  int port = 1194;
  long score = 0, speed = 0;  // NOLINT
  bool reachable = false;
  double local_ping_ms = 9999.0;
};

volatile sig_atomic_t g_keep_running = 1;
pid_t g_vpn_pid = -1;
std::chrono::steady_clock::time_point g_total_start;

void SignalHandler(int) {
  g_keep_running = 0;
  if (g_vpn_pid > 0) kill(-g_vpn_pid, SIGTERM);
}

void Usage(char* name) {
  std::cout << "fly " << kVersion << " - Minimalist VPNGate Client\n\n"
            << "Usage: " << name << " [options]\n"
            << "  -c, --country <CC>  Country (default: JP)\n"
            << "  -p, --proto <p>     Protocol: udp, tcp, all (default: udp)\n"
            << "  -a, --auto          Connect to best server immediately\n"
            << "  -n, --count <n>     Servers to show (default: 10)\n"
            << "  -v, --verbose       Show OpenVPN logs\n"
            << "  -k, --kill          Stop active VPN sessions\n"
            << "      --version       Show version information\n";
}

std::vector<std::string> Split(const std::string& s, char delimiter) {
  std::vector<std::string> tokens;
  std::string token;
  std::istringstream token_stream(s);
  while (std::getline(token_stream, token, delimiter)) tokens.push_back(token);
  return tokens;
}

VpnServer Verify(VpnServer s) {
  const int kTimeoutMs = 800;
  int sock = socket(AF_INET, (s.proto == "udp" ? SOCK_DGRAM : SOCK_STREAM), 0);
  if (sock < 0) return s;
  fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK);
  struct sockaddr_in addr = {AF_INET, htons(static_cast<uint16_t>(s.port))};
  inet_pton(AF_INET, s.ip.c_str(), &addr.sin_addr);
  auto start = std::chrono::high_resolution_clock::now();
  if (s.proto == "tcp") {
    if (connect(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0 &&
        errno != EINPROGRESS) {
      close(sock);
      return s;
    }
    struct pollfd pfd = {sock, POLLOUT, 0};
    if (poll(&pfd, 1, kTimeoutMs) > 0) {
      int err;
      socklen_t len = sizeof(err);
      getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len);
      if (err == 0) {
        s.local_ping_ms = std::chrono::duration<double, std::milli>(
                              std::chrono::high_resolution_clock::now() - start)
                              .count();
        s.reachable = true;
      }
    }
  } else {
    std::string cmd = "ping -c 1 -W 1 " + s.ip +
                      " 2>/dev/null | grep -o 'time=[0-9.]*' | cut -d= -f2";
    FILE* p = popen(cmd.c_str(), "r");
    char buf[64];
    if (p && fgets(buf, sizeof(buf), p)) {
      try {
        s.local_ping_ms = std::stod(buf);
        s.reachable = true;
      } catch (...) {
      }
    }
    if (p) pclose(p);
  }
  close(sock);
  return s;
}

std::string Base64Decode(const std::string& in) {
  static const std::string b =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  int val = 0, valb = -8;
  for (unsigned char c : in) {
    auto pos = b.find(static_cast<char>(c));
    if (pos == std::string::npos) continue;
    val = (val << 6) + static_cast<int>(pos);
    valb += 6;
    if (valb >= 0) {
      out.push_back(static_cast<char>((val >> valb) & 0xFF));
      valb -= 8;
    }
  }
  return out;
}

bool Connect(const VpnServer& s, bool verbose) {
  std::string cfg = Base64Decode(s.config_base64);
  int in_p[2], out_p[2];
  if (pipe(in_p) < 0 || pipe(out_p) < 0) return false;
  if ((g_vpn_pid = fork()) == 0) {
    setpgid(0, 0);
    dup2(in_p[0], 0);
    dup2(out_p[1], 1);
    dup2(out_p[1], 2);
    close(in_p[1]);
    close(out_p[0]);
    execlp("sudo", "sudo", "openvpn", "--config", "/dev/stdin",
           "--data-ciphers", "DEFAULT:AES-128-CBC", "--verb", "3",
           "--connect-timeout", "10", nullptr);
    _exit(1);
  }
  close(in_p[0]);
  close(out_p[1]);
  write(in_p[1], cfg.c_str(), cfg.size());
  close(in_p[1]);
  fcntl(out_p[0], F_SETFL, fcntl(out_p[0], F_GETFL, 0) | O_NONBLOCK);
  auto start = std::chrono::steady_clock::now();
  char buf[4096];
  bool connected = false;
  std::string log_acc;
  std::cout << "\033[1;34m[*]\033[0m Connecting: " << s.ip << ":" << s.port
            << "..." << std::endl;
  while (g_keep_running) {
    ssize_t n = read(out_p[0], buf, sizeof(buf) - 1);
    if (n > 0) {
      buf[n] = 0;
      std::string logs(buf);
      std::ofstream(kLogPath, std::ios::app) << logs;
      if (verbose) std::cout << "\033[2m" << logs << "\033[0m";
      log_acc += logs;
      if (!connected && log_acc.find("Sequence Completed") != std::string::npos) {
        connected = true;
        auto end = std::chrono::steady_clock::now();
        double diff = std::chrono::duration_cast<std::chrono::milliseconds>(
                          end - g_total_start)
                          .count() /
                      1000.0;
        printf("\033[1;32m[!] ONLINE in %.1fs.\033[0m\n", diff);
      }
    }
    if (!connected && std::chrono::duration_cast<std::chrono::seconds>(
                          std::chrono::steady_clock::now() - start)
                              .count() > 15)
      break;
    usleep(10000);
  }
  if (!connected) {
    kill(-g_vpn_pid, SIGTERM);
    waitpid(g_vpn_pid, nullptr, 0);
    g_vpn_pid = -1;
  } else {
    while (g_keep_running) {
      if (read(out_p[0], buf, sizeof(buf)) <= 0) {
        if (waitpid(g_vpn_pid, nullptr, WNOHANG) != 0) break;
      }
      usleep(100000);
    }
  }
  return connected;
}

}  // namespace

int main(int argc, char** argv) {
  g_total_start = std::chrono::steady_clock::now();
  if (argc == 1) {
    Usage(argv[0]);
    return 0;
  }
  Config conf;
  int opt;
  struct option long_opts[] = {
      {"country", 1, 0, 'c'}, {"proto", 1, 0, 'p'}, {"auto", 0, 0, 'a'},
      {"count", 1, 0, 'n'},   {"verbose", 0, 0, 'v'}, {"kill", 0, 0, 'k'},
      {"version", 0, 0, 'V'}, {"help", 0, 0, 'h'},   {0, 0, 0, 0}};
  while ((opt = getopt_long(argc, argv, "c:p:an:vkh", long_opts, nullptr)) != -1) {
    switch (opt) {
      case 'c': conf.country = optarg; break;
      case 'p': conf.proto = optarg; break;
      case 'a': conf.auto_connect = true; break;
      case 'n': conf.count = std::stoi(optarg); break;
      case 'v': conf.verbose = true; break;
      case 'k':
        std::system("sudo killall openvpn >/dev/null 2>&1");
        std::cout << "Cleaned up sessions.\n";
        return 0;
      case 'V': std::cout << "fly version " << kVersion << "\n"; return 0;
      default: Usage(argv[0]); return 0;
    }
  }
  signal(SIGINT, SignalHandler);
  if (system("sudo -v") != 0) return 1;
  CURL* curl = curl_easy_init();
  std::string res;
  if (!curl) return 1;
  std::cout << "\033[1;32m==>\033[0m Fetching servers..." << std::endl;
  curl_easy_setopt(curl, CURLOPT_URL, "https://www.vpngate.net/api/iphone/");
  curl_easy_setopt(
      curl, CURLOPT_WRITEFUNCTION,
      +[](void* p, size_t s, size_t n, void* d) {
        ((std::string*)d)->append((char*)p, s * n);
        return s * n;
      });
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &res);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
  CURLcode res_code = curl_easy_perform(curl);
  if (res_code != CURLE_OK) {
    std::cout << "\033[1;31m[!] Download failed: " << curl_easy_strerror(res_code)
              << "\033[0m\n";
    return 1;
  }
  curl_easy_cleanup(curl);
  std::vector<VpnServer> matches;
  std::istringstream iss(res);
  std::string line;
  while (std::getline(iss, line)) {
    auto f = Split(line, ',');
    if (f.size() < 15 || line[0] == '#' || line[0] == '*') continue;
    if (f[6] != conf.country) continue;
    VpnServer s;
    s.ip = f[1];
    s.score = std::stol(f[2]);
    s.speed = std::stol(f[4]);
    s.config_base64 = f.back();
    while (!s.config_base64.empty() &&
           (s.config_base64.back() == '\r' || s.config_base64.back() == '\n'))
      s.config_base64.pop_back();
    std::string cfg = Base64Decode(s.config_base64);
    std::istringstream css(cfg);
    std::string cl;
    s.proto = "udp";
    while (std::getline(css, cl)) {
      if (cl.find("remote ") == 0) {
        auto rf = Split(cl, ' ');
        if (rf.size() >= 3) s.port = std::stoi(rf[2]);
      } else if (cl.find("proto ") == 0) {
        s.proto = cl.substr(6, 3);
      }
    }
    if (conf.proto != "all" && s.proto != conf.proto) continue;
    matches.push_back(s);
  }
  if (matches.empty()) {
    std::cout << "\033[1;31m[!] No matching servers found.\033[0m\n";
    return 1;
  }
  std::sort(matches.begin(), matches.end(),
            [](const VpnServer& a, const VpnServer& b) {
              return a.score > b.score;
            });
  size_t probe_limit = std::min(matches.size(), static_cast<size_t>(25));
  std::cout << "\033[1;34m==>\033[0m Probing " << probe_limit << " servers..."
            << std::endl;
  std::vector<std::future<VpnServer>> futs;
  for (size_t i = 0; i < probe_limit; ++i)
    futs.push_back(std::async(std::launch::async, Verify, matches[i]));
  std::vector<VpnServer> v;
  for (auto& f : futs) {
    VpnServer s = f.get();
    if (s.reachable) {
      v.push_back(s);
      if (conf.auto_connect && s.local_ping_ms < 35.0) {
        Connect(s, conf.verbose);
        return 0;
      }
    }
  }
  std::sort(v.begin(), v.end(), [](const VpnServer& a, const VpnServer& b) {
    return a.local_ping_ms < b.local_ping_ms;
  });
  if (v.empty()) {
    std::cout << "\033[1;31m[!] All probes failed.\033[0m\n";
    return 1;
  }
  if (conf.auto_connect) {
    for (const auto& s : v)
      if (Connect(s, conf.verbose)) break;
  } else {
    printf("\033[1m%-3s  %-15s  %-6s  %-6s  %-10s  %-10s\033[0m\n", "#", "IP",
           "Port", "Proto", "Latency", "Speed");
    for (size_t i = 0; i < std::min(v.size(), static_cast<size_t>(conf.count));
         ++i) {
      printf("%-3zu  %-15s  %-6d  %-6s  \033[1;33m%6.1fms\033[0m  %6.1f Mbps\n",
             i + 1, v[i].ip.c_str(), v[i].port, v[i].proto.c_str(),
             v[i].local_ping_ms, v[i].speed / 1000000.0);
    }
    std::cout << "\nChoice: ";
    std::string choice_str;
    std::cin >> choice_str;
    try {
      int c = std::stoi(choice_str);
      if (c > 0 && c <= static_cast<int>(v.size()))
        Connect(v[c - 1], conf.verbose);
    } catch (...) {
    }
  }
  return 0;
}
