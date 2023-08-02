
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <getopt.h>
#include <limits.h>
#include <stdint.h>
#include <signal.h>
#include <vector>
#include <algorithm>
#include <cassert>

#include "pvxs/client.h"
#include "pvxs/data.h"

#include "bld-proto.h"

#define MAXLINE 9000

#define CHANNEL_SIZE 4

#if __cplusplus >= 201103L
#define CONSTEXPR constexpr
#else
#define CONSTEXPR static const
#endif

using ChannelType = pvxs::TypeCode::code_t;

static void print_data(uint32_t* data, size_t num, const std::vector<ChannelType>& formats, const std::vector<int>& channels);
static int num_str_base(const char* str);
static void usage();
static std::vector<ChannelType> parse_channel_formats(const char* str);
static std::vector<int> parse_channels(const char* str);
static std::vector<int> parse_events(const char* str);
static std::vector<ChannelType> read_channel_formats(const char* str);
static void build_channel_list();
static void extract_ts(uint64_t ts, uint32_t& sec, uint32_t& nsec);
static char* format_ts(uint32_t sec, uint32_t nsec);

template<class T, size_t N>
CONSTEXPR size_t arrayLength(const T (&array)[N]) {
    return N;
}

template<size_t N>
void strcpy_safe(char (&dest)[N], const char* s) {
    strncpy(dest, s, N-1);
    dest[N-1] = 0;
}

static void timeoutHandler(int) {
    printf("Timeout exceeded, exiting!\n");
    exit(1);
}

static int show_data = 0;
static int unicast = 0;
static int verbose = 0;
static std::vector<int> enabled_channels;
static std::vector<ChannelType> channel_formats;
static std::vector<int> events;
static int channel_remap[NUM_BLD_CHANNELS];     // Maps payload channels to their actual channel number

// List of channel labels
static std::vector<std::string> channel_labels = []() -> std::vector<std::string> {
    std::vector<std::string> labels;
    for (int i = 0; i < NUM_BLD_CHANNELS; ++i) {
        char ch[128];
        snprintf(ch, sizeof(ch), "ch%02d", i);
        labels.push_back(ch);
    }
    return labels;
}();

#define LOG_VERBOSE(...) if (verbose) { printf(__VA_ARGS__); }

static option long_opts[] = {
    {"port", required_argument, NULL, 'p'},
    {"show-data", no_argument, &show_data, 'd'},
    {"version", required_argument, NULL, 'k'},
    {"severity", required_argument, NULL, 's'},
    {"timeout", required_argument, NULL, 't'},
    {"num", required_argument, NULL, 'n'},
    {"format", required_argument, NULL, 'f'},
    {"unicast", no_argument, &unicast, 'u'},
    {"channels", required_argument, NULL, 'c'},
    {"help", no_argument, NULL, 'h'},
    {"events", required_argument, NULL, 'e'},
    {"pv", required_argument, NULL, 'b'},
    {"verbose", no_argument, &verbose, 'v'},
    {"address", required_argument, NULL, 'a'},
};

static const char* help_text[] = {
    "The port to use (default: 50000)",
    "Display event data",
    "Filter packets by this version",
    "Filter packets by this severity mask",
    "Timeout to receive packets",
    "Number of packets to receive before exiting",
    "Data format (i.e. 'f,u,i,f' for float, uint32, int32, float)",
    "Receive packets as unicast too",
    "Channels to display, comma separated list",
    "Display this help text",
    "Event numbers to display",
    "PV that contains a description of the BLD payload",
    "Run in verbose mode, showing additional debugging info",
    "Multicast address",
};

STATIC_ASSERT(arrayLength(long_opts) == arrayLength(help_text));

int main(int argc, char *argv[]) {
    int sockfd;
    char buffer[MAXLINE];

    char mcastAddr[256] = "224.0.0.0";
    int port = DEFAULT_BLD_PORT, needsSevr = 0;
    int64_t version = -1, numPackets = INT64_MAX;
    uint64_t timeout = UINT64_MAX;
    uint64_t sevrMask = 0;

    for (int i = 0; i < arrayLength(channel_remap); ++i)
        channel_remap[i] = i;

    signal(SIGALRM, timeoutHandler);

    int opt = 0, longind = 0;
    while ((opt = getopt_long(argc, argv, "vuhdp:k:s:t:n:f:c:e:b:", long_opts, &longind)) != -1) {
        /* Handle long opts */
        if (opt == 0) {
            if (long_opts[longind].val != 0)
                opt = long_opts[longind].val;
        }

        switch(opt) {
        case 0:
            break;
        case 'v':
            verbose = 1;
            break;
        case 'd':
            show_data = 1;
            break;
        case 'p':
            port = atoi(optarg);
            break;
        case 'k':
            version = atoll(optarg);
            break;
        case 's':
            sevrMask = strtoull(optarg, NULL, num_str_base(optarg));
            needsSevr = 1;
            break;
        case 't':
            timeout = strtoull(optarg, NULL, num_str_base(optarg));
            break;
        case 'n':
            numPackets = strtoull(optarg, NULL, num_str_base(optarg));
            break;
        case 'h':
            usage();
            exit(0);
        case 'f':
            channel_formats = parse_channel_formats(optarg);
            break;
        case 'c':
            enabled_channels = parse_channels(optarg);
            break;
        case 'e':
            events = parse_events(optarg);
            break;
        case 'b':
            channel_formats = read_channel_formats(optarg);
            break;
        case 'u':
            unicast = 1;
            break;
        case 'a':
            strcpy_safe(mcastAddr, optarg);
            break;
        case '?':
            usage();
            exit(EXIT_FAILURE);
            break;
        }
    }

    if (!enabled_channels.empty())
        build_channel_list();

    if (timeout != UINT_MAX)
        alarm(timeout);

    struct sockaddr_in servaddr, cliaddr;
    bldMulticastPacket_t *ptr;
    bldMulticastComplementaryPacket_t *compptr;

    // Creating socket file descriptor
    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));
    memset(&cliaddr, 0, sizeof(cliaddr));

    // Filling server information
    servaddr.sin_family = AF_INET; // IPv4
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(port);

    // Bind the socket with the server address
    if ( bind(sockfd, (const struct sockaddr *)&servaddr,
            sizeof(servaddr)) < 0 )
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // If we're multicast, add ourselves to the group
    if (!unicast) {
        printf("Listening for multicast packets on %s\n", mcastAddr);
        ip_mreq mreq;
        mreq.imr_interface.s_addr = INADDR_ANY;
        mreq.imr_multiaddr.s_addr = inet_addr(mcastAddr);

        if (setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
            perror("failed to opt into multicast: setsockoptfailed");
            exit(EXIT_FAILURE);
        }
    }

    const bool ignoreFirst = !events.empty() && std::find(events.begin(), events.end(), 0) == events.end();

    while(1)
    {
        // Clear buffer so we can easily cast to our structure types without printing junk
        memset(buffer, 0, sizeof(buffer));

        if (numPackets-- <= 0)
            break;

        char * bufptr = buffer;
        socklen_t len = sizeof(cliaddr); //len is value/result

        ssize_t n = recvfrom(sockfd, (char *)buffer, MAXLINE,
                                MSG_WAITALL, ( struct sockaddr *) &cliaddr,
                                &len);
        if (n < 0) {
            perror("recvfrom failed");
            exit(EXIT_FAILURE);
        }

        size_t packSize = n < sizeof(bldMulticastPacket_t) ? n : sizeof(bldMulticastPacket_t);
        ptr = (bldMulticastPacket_t *)buffer;

        // Check if we need to skip this packet
        if (version >= 0 && ptr->version != version)
            continue;

        // Now check if severity mask matches
        if (needsSevr && ptr->severityMask != sevrMask)
            continue;

        // Packet accepted for display, cancel any pending timeouts
        alarm(0);

        printf("====== new packet size %li ======\n", n);

        LOG_VERBOSE("Received size: %li\n", n);

        const auto numChannels = (packSize - (sizeof(bldMulticastPacket_t) - sizeof(ptr->signals))) / CHANNEL_SIZE;

        if (!ignoreFirst) {
            uint32_t sec, nsec;
            extract_ts(ptr->timeStamp, sec, nsec);

            time_t sect = sec;
            auto tinfo = localtime(&sect);
            char tmbuf[64];
            strftime(tmbuf, sizeof(tmbuf), "%Y:%m:%d %H:%M:%S", tinfo);

            printf("Num channels : %lu\n", numChannels);
            printf("timeStamp    : 0x%016lX %u sec, %u nsec (%s)\n", ptr->timeStamp, sec, nsec, format_ts(sec, nsec));
            printf("pulseID      : 0x%016lX\n", ptr->pulseID);
            printf("severityMask : 0x%016lX\n", ptr->severityMask);
            printf("version      : 0x%08X\n", ptr->version);

            // Display payload
            if (show_data)
                print_data(ptr->signals, numChannels, channel_formats, enabled_channels);
        }

        n -= len < sizeof(bldMulticastPacket_t) ? len : sizeof(bldMulticastPacket_t);
        LOG_VERBOSE("n is %li size of packet=%lu eventData=%lu\n", n, sizeof(bldMulticastPacket_t), sizeof(bldMulticastComplementaryPacket_t));
        bufptr = bufptr + sizeof(bldMulticastPacket_t);
        compptr = (bldMulticastComplementaryPacket_t *)bufptr;

        // Display additional events
        int eventNum = 1;
        while (n > 0)
        {
            // Skip the event if requested
            if (events.empty() || std::find(events.begin(), events.end(), eventNum) != events.end()) {
                // Compute new timestamp and pulse ID
                uint64_t newTS = compptr->deltaTimeStamp + ptr->timeStamp;
                uint64_t newPulse = compptr->deltaPulseID + ptr->pulseID;
                
                uint32_t sec, nsec;
                extract_ts(newTS, sec, nsec);

                printf("===> event %d\n", eventNum);
                printf("Timestamp     : 0x%016lX %u sec, %u nsec (%s) delta 0x%X\n", newTS, sec, nsec, format_ts(sec, nsec), compptr->deltaTimeStamp);
                printf("Pulse ID      : 0x%016lX delta 0x%X\n", newPulse, compptr->deltaPulseID);
                printf("severity mask : 0x%016lX\n", compptr->severityMask);
                if (show_data)
                    print_data(compptr->signals, numChannels, channel_formats, enabled_channels);
            }

            n -= sizeof(bldMulticastComplementaryPacket_t);
            compptr = (bldMulticastComplementaryPacket_t *) (bufptr + sizeof(bldMulticastComplementaryPacket_t));

            LOG_VERBOSE("%li bytes remaining\n", n < 0 ? 0 : n);
            eventNum++;
        } 
        printf("====== Packet finished ======\n");

    }
    return 0;
}

static int num_str_base(const char* str) {
    if (str[0] == '0') {
        switch(str[1]) {
        case 'x':
            return 16;
        case 'b':
            return 2;
        case 'o':
            return 8;
        default:
            return 10;
        }
    }
    return 10;
}

static void usage() {
    printf("USAGE: bldDecode [ARGS]\n");
    printf("Options:\n");
    for (size_t i = 0; i < arrayLength(long_opts); ++i) {
        char buf[512];
        snprintf(buf, sizeof(buf), "  -%c%s, --%s%s",
            long_opts[i].val,
            long_opts[i].has_arg == no_argument ? "" : " <arg>",
            long_opts[i].name,
            long_opts[i].has_arg == no_argument ? "" : "=<arg>");
        printf("%-30s %s\n", buf, help_text[i]);
    }
}

static void print_single_channel(int index, uint32_t data, pvxs::TypeCode format) {
    printf("  %s raw=0x%08X, ", channel_labels[index].c_str(), data);
    switch(format.code) {
    case pvxs::TypeCode::Float32:
        printf("float=%g\n", *reinterpret_cast<float*>(&data));
        break;
    case pvxs::TypeCode::Int32:
        printf("int32=%d\n", *reinterpret_cast<int*>(&data));
        break;
    case pvxs::TypeCode::UInt32:
        printf("uint32=%u\n", data);
        break;
    default:
        assert(0);
        break;
    }
}

static void print_data(uint32_t* data, size_t num, const std::vector<pvxs::TypeCode::code_t>& formats, const std::vector<int>& channels) {
    printf("Data payload:\n");

    // A bit ugly, but we need to pad out the channel formats if num > formats.size()
    std::vector<ChannelType> actualFormats = formats;
    while(actualFormats.size() < num)
        actualFormats.push_back(ChannelType::UInt32);

    if (channels.empty()) {
        for (size_t i = 0; i < num; ++i)
            print_single_channel(i, data[i], actualFormats[i]);
    }
    else {
        for (auto chan : channels) {
            if (size_t(chan) >= num)
                continue; // Skip anything we don't have
            print_single_channel(chan, data[chan], actualFormats[chan]);
        }
    }
}

static std::vector<ChannelType> parse_channel_formats(const char* str) {
    char buf[512];
    strcpy_safe(buf, str);

    std::vector<ChannelType> fmt;
    for (char* s = strtok(buf, ", "); s; s = strtok(nullptr, ", ")) {
        switch(*s) {
        case 'f':
            fmt.push_back(ChannelType::Float32);
            break;
        case 'i':
            fmt.push_back(ChannelType::Int32);
            break;
        case 'u':
            fmt.push_back(ChannelType::UInt32);
            break;
        default:
            printf("Unknown format '%c'! Valid types are 'f', 'i', and 'u'", *s);
            exit(1);
            return {};
        }
    }
    return fmt;
}

static std::vector<int> parse_channels(const char* str) {
    char buf[512];
    strcpy_safe(buf, str);

    std::vector<int> channels;
    for (char* s = strtok(buf, ", "); s; s = strtok(nullptr, ", ")) {
        channels.push_back(strtol(s, NULL, 10));
        if (channels.back() < 0 || channels.back() >= NUM_BLD_CHANNELS) {
            printf("Invalid channel index %d!\n", channels.back());
            exit(1);
        }
    }
    std::sort(channels.begin(), channels.end(), [](int a, int b) { return a < b; });
    return channels;
}

static std::vector<int> parse_events(const char* str) {
    char buf[512];
    strcpy_safe(buf, str);

    std::vector<int> evs;
    for (char* s = strtok(buf, ", "); s; s = strtok(nullptr, ", ")) {
        auto ev = strtol(s, nullptr, 10);
        if (ev < 0) {
            printf("Invalid event number %li\n", ev);
            exit(1);
        }
        evs.push_back(ev);
    }
    return evs;
}

static std::vector<ChannelType> read_channel_formats(const char* str) {
    using namespace pvxs;

    auto ctx = client::Context::fromEnv();
    
    LOG_VERBOSE("Read payload PV: %s\n", str);
    Value result;
    try {
        result = ctx.get(str).exec()->wait(10.0);
    }
    catch(pvxs::client::Timeout& e) {
        printf("Timeout while reading PV '%s', please specify channel formats manually with -f\n", str);
        exit(1);
    }

    if (result.type() != TypeCode::Struct) {
        printf("Payload PV '%s' is not of the expected type 'Struct'\n", str);
        exit(1);
    }
    
    auto structure = result["BldPayload"];
    if (!structure.valid()) {
        printf("Payload PV '%s' contains no 'BldPayload' field\n", str);
        exit(1);
    }

    channel_labels.clear();

    std::vector<ChannelType> format;
    for (int i = 0, chi = 0; i < NUM_BLD_CHANNELS; ++i) {
        char signalName[128];
        snprintf(signalName, sizeof(signalName), "signal%02d", i);
        const auto v = structure[signalName];
        LOG_VERBOSE("%s: valid=%d isFloat=%d\n", signalName, v.valid(), v.type().code == TypeCode::Float32);
        if (v.valid()) {
            format.push_back(v.type().code);
            
            // Generate label for display
            char ch[128];
            snprintf(ch, sizeof(ch), "ch%02d", i);
            channel_labels.push_back(ch);

            // Store off remap
            channel_remap[i] = chi++;
        }
    }

    return format;
}

static void build_channel_list() {
    std::vector<int> chanList;
    
    // Remap user-provided enabled channels to the ones specified by BLD_PAYLOAD
    for (auto c : enabled_channels) {
        assert(c >= 0 && c < NUM_BLD_CHANNELS);
        chanList.push_back(channel_remap[c]);
        LOG_VERBOSE("remap: %d -> %d\n", c, channel_remap[c]);
    }
    enabled_channels = chanList;
}

static void extract_ts(uint64_t ts, uint32_t& sec, uint32_t& nsec) {
    nsec = ts & 0xFFFFFFFF;
    sec = (ts>>32) & 0xFFFFFFFF;
}

static char* format_ts(uint32_t sec, uint32_t nsec) {
    time_t sect = sec;
    auto tinfo = localtime(&sect);
    
    static char tmbuf[128] {};
    strftime(tmbuf, sizeof(tmbuf), "%Y:%m:%d %H:%M:%S", tinfo);
    return tmbuf;
}
