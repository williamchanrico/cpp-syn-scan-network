/*
* Title: Syn Scan Network
* Description: Scan if some ports are open by sending SYN packets to all IP(s) in a network
* Date: 29-Apr-2018
* Author: William Chanrico
*/
#include <arpa/inet.h>
#include <cstdlib>
#include <inttypes.h>
#include <iomanip>
#include <iostream>
#include <math.h>
#include <netdb.h>
#include <pthread.h>
#include <set>
#include <stdarg.h>
#include <string>
#include <unistd.h>
#include <vector>

/* https://github.com/mfontanini/libtins */
#include <tins/address_range.h>
#include <tins/ethernetII.h>
#include <tins/ip.h>
#include <tins/ip_address.h>
#include <tins/network_interface.h>
#include <tins/packet_sender.h>
#include <tins/sniffer.h>
#include <tins/tcp.h>
#include <tins/utils.h>

using namespace Tins;

#define RATE_LIMIT 100

void start_scan(int argc, char* argv[]);
int parse_cidr(const char* cidr, struct in_addr* addr, struct in_addr* mask);
const char* dotted_quad(const struct in_addr* addr);
AddressRange<IPv4Address> parse_target(char* target);
std::string ip_to_host(const char* ip);

class Scanner {
public:
    Scanner(const NetworkInterface& interface,
        const AddressRange<IPv4Address>& target_addresses,
        const std::vector<std::string>& target_ports);

    void run();

private:
    void send_syn_packets(const NetworkInterface& iface);
    bool callback(PDU& pdu);
    void launch_sniffer();
    static void* thread_proc(void* arg);
    void start_clock();
    void end_clock();

    NetworkInterface iface;
    AddressRange<IPv4Address> target_addresses;
    std::set<uint16_t> target_ports;
    Sniffer sniffer;

    std::set<std::string> open_hosts;
    double program_duration;
    struct timespec start_time, finish_time;
};

int main(int argc, char* argv[])
{
    if (argc != 3) {
        std::cout << "Usage: " << argv[0] << " <IP/CIDR> <Port1,Port2,...>\n";
        std::cout << "Example:\n";
        std::cout << "\t" << argv[0] << " 166.104.0.0/16 80,443,8080\n";
        std::cout << "\t" << argv[0] << " 35.186.153.3 80,443,8080\n";
        std::cout << "\t" << argv[0] << " 166.104.177.24 80\n";

        return 1;
    }

    try {
        start_scan(argc, argv);
    } catch (std::runtime_error& e) {
        std::cerr << e.what() << std::endl;
    }
}

/**
  Constructor for the Scanner class
 */
Scanner::Scanner(const NetworkInterface& interface,
    const AddressRange<IPv4Address>& target_addresses,
    const std::vector<std::string>& target_ports)
    : iface(interface)
    , target_addresses(target_addresses)
    , sniffer(interface.name())
{
    // sniffer.set_filter(
    //     "tcp and ip src " + target_addresses.to_string() + " and tcp[tcpflags] & (tcp-rst|tcp-syn) != 0"
    // );

    for (size_t a = 0; a < target_ports.size(); a++) {
        this->target_ports.insert(atoi(target_ports[a].c_str()));
    }
}

/**
  The function for sniffer thread
 */
void* Scanner::thread_proc(void* arg)
{
    Scanner* scanner = (Scanner*)arg;
    scanner->launch_sniffer();

    return NULL;
}

/**
  Launch the sniffer process
 */
void Scanner::launch_sniffer()
{
    sniffer.sniff_loop(make_sniffer_handler(this, &Scanner::callback));
}

/**
  Sniffer's callback to handle replies from target hosts
 */
bool Scanner::callback(PDU& pdu)
{
    const IP& ip = pdu.rfind_pdu<IP>();
    const TCP& tcp = pdu.rfind_pdu<TCP>();

    if (target_addresses.contains(ip.src_addr()) && target_ports.count(tcp.sport()) == 1) {
        std::string ip_address = ip.src_addr().to_string();

        if (tcp.get_flag(TCP::RST)) {
            if (tcp.get_flag(TCP::SYN))
                return false;
            // std::cout << ip_address << " (" << ip_to_host(ip_address.c_str()) << ")\tPort: " << tcp.sport() << " closed\n";
        } else if (tcp.flags() == (TCP::SYN | TCP::ACK)) {
            std::cout << ip_address << " (" << ip_to_host(ip_address.c_str()) << ")\t\tPort: " << tcp.sport() << " open\n";
            open_hosts.insert(ip_address);
        }
    }
    return true;
}

/**
  Start the scan process
 */
void Scanner::run()
{
    start_clock();

    pthread_t thread;
    pthread_create(&thread, 0, &Scanner::thread_proc, this);
    send_syn_packets(iface);

    void* dummy;
    pthread_join(thread, &dummy);

    std::cout << "\nTotal open hosts: " << open_hosts.size() << " host(s)" << std::endl;

    end_clock();
}

/**
  Send the SYN packets all at once to target_addresses
 */
void Scanner::send_syn_packets(const NetworkInterface& iface)
{
    PacketSender sender;
    NetworkInterface::Info info = iface.addresses();
    IP ip = IP(*target_addresses.begin(), info.ip_addr) / TCP();
    TCP& tcp = ip.rfind_pdu<TCP>();
    tcp.set_flag(TCP::SYN, 1);
    tcp.sport(46156);

    unsigned rate_limit_counter = 1;
    open_hosts.clear();
    for (const auto& addr : target_addresses) {
        for (std::set<uint16_t>::const_iterator it = target_ports.begin(); it != target_ports.end(); ++it) {
            if (rate_limit_counter % RATE_LIMIT == 0)
                sleep(1);

            ip.dst_addr(addr);
            tcp.dport(*it);
            sender.send(ip);

            rate_limit_counter = (rate_limit_counter + 1) % RATE_LIMIT;
        }
    }

    tcp.set_flag(TCP::RST, 1);
    tcp.sport(*target_ports.begin());
    ip.src_addr(*target_addresses.begin());

    EthernetII eth = EthernetII(info.hw_addr, info.hw_addr) / ip;
    sender.send(eth, iface);
}

/**
  To mark the beginning of the scan, will initialize start_time variable
 */
void Scanner::start_clock()
{
    clock_gettime(CLOCK_MONOTONIC, &start_time);
}

/**
  To mark the end of the scan, will output the scan duration
 */
void Scanner::end_clock()
{
    clock_gettime(CLOCK_MONOTONIC, &finish_time);
    program_duration = (finish_time.tv_sec - start_time.tv_sec);
    program_duration += (finish_time.tv_nsec - start_time.tv_nsec) / 1000000000.0;

    int hours_duration = program_duration / 3600;
    int mins_duration = (int)(program_duration / 60) % 60;
    double secs_duration = fmod(program_duration, 60);

    std::cout << "Scan duration: " << hours_duration << " hour(s) " << mins_duration << " min(s) " << std::setprecision(5) << secs_duration << " sec(s)\n";
}

/**
  This is where the Scanner class will be used
 */
void start_scan(int argc, char* argv[])
{
    NetworkInterface iface = NetworkInterface::default_interface();
    std::cout << "Running on interface: " << iface.name() << "\n";
    std::cout << "SYN scan [" << argv[1] << "]:[" << argv[2] << "]\n";

    AddressRange<IPv4Address> target_addresses = parse_target(argv[1]);

    char* port_list = (char*)malloc(strlen(argv[2]) + 1);
    strcpy(port_list, argv[2]);

    std::vector<std::string> target_ports;
    char* pch = strtok(port_list, ",");
    while (pch != NULL) {
        std::string port(pch);
        target_ports.push_back(port);
        pch = strtok(NULL, ",");
    }

    Scanner scanner(iface, target_addresses, target_ports);
    scanner.run();
}

/**
  Format the IPv4 address in dotted quad notation, using a static buffer
 */
const char* dotted_quad(const struct in_addr* addr)
{
    static char buf[INET_ADDRSTRLEN];

    return inet_ntop(AF_INET, addr, buf, sizeof buf);
}

/**
  Parse CIDR notation address.
  Return the number of bits in the netmask if the string is valid
  Return -1 if the string is invalid.
 */
int parse_cidr(const char* cidr, struct in_addr* addr, struct in_addr* mask)
{
    int bits = inet_net_pton(AF_INET, cidr, addr, sizeof addr);

    mask->s_addr = htonl(~(bits == 32 ? 0 : ~0U >> bits));
    return bits;
}

/**
  Parse target IP into AddressRange<IPv4Address> type
 */
AddressRange<IPv4Address> parse_target(char* target)
{
    struct in_addr parsed_in_addr, mask_in_addr, wildcard_in_addr, network_in_addr, broadcast_in_addr, min_in_addr, max_in_addr;

    int bits = parse_cidr(target, &parsed_in_addr, &mask_in_addr);
    if (bits == -1) {
        std::cerr << "Invalid network address" << std::endl;
        exit(1);
    }

    wildcard_in_addr = mask_in_addr;
    wildcard_in_addr.s_addr = ~wildcard_in_addr.s_addr;

    network_in_addr = parsed_in_addr;
    network_in_addr.s_addr &= mask_in_addr.s_addr;

    broadcast_in_addr = parsed_in_addr;
    broadcast_in_addr.s_addr |= wildcard_in_addr.s_addr;

    min_in_addr = network_in_addr;
    max_in_addr = broadcast_in_addr;

    if (network_in_addr.s_addr != broadcast_in_addr.s_addr) {
        min_in_addr.s_addr = htonl(ntohl(min_in_addr.s_addr) + 1);
        max_in_addr.s_addr = htonl(ntohl(max_in_addr.s_addr) - 1);
    }

    int num_hosts = (int64_t)ntohl(broadcast_in_addr.s_addr) - ntohl(network_in_addr.s_addr) + 1;
    std::string min_ip(dotted_quad(&min_in_addr));
    std::string max_ip(dotted_quad(&max_in_addr));
    AddressRange<IPv4Address> range(min_ip, max_ip);

    std::cout << num_hosts << " host(s): " << min_ip << " -> " << max_ip << "\n\n";

    return range;
}

/**
 Get hostname of an IP address
 */
std::string ip_to_host(const char* ip)
{
    struct sockaddr_in dest;
    char buffer[NI_MAXHOST];

    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(ip);
    dest.sin_port = 0;

    if (getnameinfo((struct sockaddr*)&dest, sizeof(dest), buffer, NI_MAXHOST, NULL, 0, NI_NAMEREQD) != 0)
        strcpy(buffer, " ");

    return std::string(buffer);
}
