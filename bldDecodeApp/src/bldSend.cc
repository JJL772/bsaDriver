/**
 * Simple BLD test sender. Used to test the wireshark plugin impl
 * @author Jeremy Lorelli
 * @date July 25th, 2023
 */

#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <sys/time.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "bld-proto.h"

void usage(const char* argv0) {
    printf("%s -a x.x.x.x -p # [-s # -f # -v # -i #]\n", argv0);
    printf("  -a # - IP address to send multicast over\n");
    printf("  -p # - Port to use\n");
    printf("  -s # - Severity mask to use\n");
    printf("  -v # - Version to use\n");
    printf("  -f # - Beam frequency (in Hz)\n");
    printf("  -i # - Interval to send BLD packets at, in ms (Default 1000)\n");
    printf("  -c # - Number of channels in output, 0-31\n");
	printf("  -e # - Number of complementary frames to send\n");
}

double cur_time(struct timespec* tp) {
    struct timespec g;
    if (!tp) {
        tp = &g;
        clock_gettime(CLOCK_MONOTONIC, tp);
    }
    return (double)tp->tv_sec + tp->tv_nsec / 1e9;
}

struct timespec time_to_ts(double seconds) {
    double rem = fmod(seconds, 1.0);
    struct timespec tp;
    tp.tv_sec = rint(seconds);
    tp.tv_nsec = rem * 1e9;
    return tp;
}

int main(int argc, char** argv) {
    
    int port = DEFAULT_BLD_PORT;
    uint64_t sevr = 0, pulse = 0, beamFreq = 1000;
    uint32_t ver = 0, chans = 0, comp = 0;
    double interval = 1;
    char ip[128];

    memset(ip, 0, sizeof(ip));

    int opt = -1;
    while ((opt = getopt(argc, argv, "e:c:hp:s:v:f:i:a:")) != -1) {
        switch(opt) {
        case 'p':
            port = strtol(optarg, NULL, 10);
            break;
        case 's':
            sevr = strtoul(optarg, NULL, 16);
            break;
        case 'v':
            ver = strtoul(optarg, NULL, 16);
            break;
        case 'f':
            beamFreq = strtoull(optarg, NULL, 10);
            break;
        case 'i':
            interval = strtod(optarg, NULL) / 1000.0;
            break;
		case 'e':
			comp = strtol(optarg, NULL, 10);
			break;
        case 'h':
            usage(argv[0]);
            exit(1);
            break;
        case 'c':
            chans = strtoul(optarg, NULL, 10);
            if (chans > NUM_BLD_CHANNELS) {
                printf("Too many channels, %d is the max!\n", NUM_BLD_CHANNELS);
                usage(argv[0]);
                exit(1);
            }
            break;
        case 'a':
            strncpy(ip, optarg, sizeof(ip)-1);
            break;
        case '?':
            printf("Unknown arg\n");
            usage(argv[0]);
            exit(1);
            break;
        default: break;
        }
    }

    if (!ip[0]) {
        printf("You must provide an IP!\n");
        usage(argv[0]);
        return 1;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("Socket open failed");
        return 1;
    }

    struct sockaddr_in s;
    s.sin_port = htons(port);
    s.sin_addr.s_addr = inet_addr(ip);
    s.sin_family = AF_INET;

    if (bind(fd, (struct sockaddr*)&s, sizeof(s)) < 0) {
        perror("Socket bind failed");
        return 1;
    }

    /* Configure the socket for multicast */
    struct in_addr mcaddr;
    mcaddr.s_addr = inet_addr(ip);
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, (char*)&mcaddr, sizeof(mcaddr)) < 0) {
        perror("Failed to configure socket for multicast");
        return 1;
    }

    /* Compute starting time */
    double starttime = cur_time(NULL);

    const struct timespec sleep = time_to_ts(interval);

    printf("Beam running at %lu Hz, BLD interval %g seconds\n",
        beamFreq, interval);

    while(1) {

        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        double t = cur_time(&now) - starttime;
       
		char data[90000];
		char *pdat = data;

        bldMulticastPacket_t packet;
        packet.pulseID = t * beamFreq;
        packet.severityMask = sevr;
        packet.timeStamp = ((now.tv_sec << 32) & 0xFFFFFFFF00000000) | (now.tv_nsec & 0xFFFFFFFF);
        packet.version = ver;
        
        for (int i = 0; i < chans; ++i) {
            packet.signals[i] = 1;
        }

        size_t packetSize = bldMulticastPacketHeaderSize + chans * sizeof(uint32_t);
		memcpy(data, &packet, packetSize);
		pdat += packetSize;

		for (int i = 0; i < comp; ++i) {
			bldMulticastComplementaryPacket_t c;
			c.deltaPulseID = rand() % (1<<12);
			c.deltaTimeStamp = rand() % (1<<10);
			c.severityMask = sevr;
			for (int sig = 0; sig < chans; ++sig)
				c.signals[sig] = 2;
			size_t cSize = sizeof(c) - sizeof(uint32_t)*(NUM_BLD_CHANNELS-chans);
			memcpy(pdat, &c, cSize);
			pdat += cSize;
			packetSize += cSize;
		}

        if (sendto(fd, data, packetSize, 0, (struct sockaddr*)&s, sizeof(s)) < 0) {
            perror("Send failed");
        }

        struct timespec rem;
        nanosleep(&sleep, &rem);
    }

    close(fd);
    return 0;
}
