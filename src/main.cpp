#include <iostream>
#include <cstring>
#include <flog.h>

#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <unistd.h>
#include <sys/signal.h>
#include <pty.h>

extern "C" {
#define BUILD_RADIO_IFACE
#include "cats/radio_iface.h"
#include "cats/packet.h"
#include "cats/error.h"
}

static int radio_fd;
static int slave_pty;
static std::string serial_port;
static const uint8_t CBOR_BEGIN[3] = { 0xd9, 0xd9, 0xf7 };

void print_packet(cats_packet_t* pkt)
{
    cats_whisker_data_t* data;
    if(cats_packet_get_identification(pkt, (cats_ident_whisker_t**)&data) == CATS_SUCCESS) {
        printf("IDENT: \t%s-%d [ICON: %d]\n", 
                data->identification.callsign, 
                data->identification.ssid, 
                data->identification.icon
        );
    }
    if(cats_packet_get_route(pkt, (cats_route_whisker_t**)&data) == CATS_SUCCESS) {
        printf("ROUTE: \t(MAX %d) ", data->route.max_digipeats);
        cats_route_hop_t* hop = &(data->route.hops);
        while(hop != NULL) {
            if(hop->hop_type == CATS_ROUTE_INET) {
                printf("[NET]");
            }
            else if(hop->hop_type == CATS_ROUTE_FUTURE) {
                printf("%s-%d*", hop->callsign, hop->ssid);
            }
            else if(hop->hop_type == CATS_ROUTE_PAST) {
                printf("%s-%d [%.1f dBm]", hop->callsign, hop->ssid, hop->rssi);
            }
            if(hop->next != NULL) {
                printf(" -> ");
            }
            hop = hop->next;
        }
        printf("\n");
    }
    char comment[CATS_MAX_PKT_LEN];
    if(cats_packet_get_comment(pkt, comment) == CATS_SUCCESS) {
        printf("CMNT: \t'%s'\n", comment);
    }
    if(cats_packet_get_gps(pkt, (cats_gps_whisker_t**)&data) == CATS_SUCCESS) {
        printf("GPS: \t(%.4f, %.4f) +/- %d m, v = %.2f m/s [N %.2f] deg\nALT: \t%.2f m\n",
                data->gps.latitude,
                data->gps.longitude,
                data->gps.max_error,
                data->gps.speed,
                data->gps.heading,
                data->gps.altitude
        );
    }
    if(cats_packet_get_nodeinfo(pkt, (cats_nodeinfo_whisker_t**)&data) == CATS_SUCCESS) {
        if(data->node_info.hardware_id.enabled && data->node_info.software_id.enabled) {
            printf("HW: \t0x%04x SW: 0x%02x\n", data->node_info.hardware_id.val, data->node_info.software_id.val);
        }
        else if(data->node_info.hardware_id.enabled) {
            printf("HW: \t0x%04x\n", data->node_info.hardware_id.val);
        }
        else if(data->node_info.software_id.enabled) {
            printf("SW: \t0x%02x\n", data->node_info.software_id.val);
        }

        if(data->node_info.uptime.enabled) {
            printf("UTIME: \t%d s\n", data->node_info.uptime.val);
        }
        if(data->node_info.ant_height.enabled) {
            printf("VERT: \t%d m\n", data->node_info.ant_height.val);
        }
        if(data->node_info.ant_gain.enabled) {
            printf("GAIN: \t%.2f dBi\n", data->node_info.ant_gain.val);
        }
        if(data->node_info.tx_power.enabled) {
            printf("TXP: \t%d dBm\n", data->node_info.tx_power.val);
        }
        if(data->node_info.voltage.enabled) {
            printf("VOLTS: \t%d V\n", data->node_info.voltage.val);
        }
        if(data->node_info.temperature.enabled) {
            printf("TEMP: \t%d C\n", data->node_info.temperature.val);
        }
    }
	cats_whisker_t** arbitrary;
	if((cats_packet_get_arbitrary(pkt, &arbitrary) != CATS_FAIL)
	&& arbitrary[0]->data.raw[0] == 0xc0) {
		printf("SRC: \tAPRS\n");
	}
	else {
		printf("SRC: \tCATS\n");
	}

    printf("\n");
}

void rx_callback(int sig)
{
	static int buf_ptr = 0;
	static uint8_t buffer[CATS_MAX_PKT_LEN];
	int len = read(radio_fd, buffer + buf_ptr, CATS_MAX_PKT_LEN - buf_ptr);
	if(len < 0) {
		flog::error("Failed to read from serial port");
		return;
	}
	buf_ptr += len;

	if(buf_ptr < 3) {
		return;
	}
	if(memcmp(buffer, CBOR_BEGIN, 3) != 0) {
		flog::error("Invalid packet");
		memset(buffer, 0, CATS_MAX_PKT_LEN);
		buf_ptr = 0;
		return;
	}

	float rssi = 0;
	int r = cats_radio_iface_decode(buffer, buf_ptr, &rssi);
	if(r == CATS_FAIL) {
		flog::error("Failed to decode packet");
		return;
	}

	cats_packet_t* pkt;
	cats_packet_prepare(&pkt);
	if(cats_packet_semi_decode(pkt, buffer, r) == CATS_FAIL) {
		flog::error("Failed to decode packet");
		memset(buffer, 0, CATS_MAX_PKT_LEN);
		buf_ptr = 0;
		cats_packet_destroy(&pkt);
		return;
	}

	flog::info("SERIAL READ:");
	print_packet(pkt);	
}

void open_pty()
{
	struct termios tty;
	std::memset(&tty, 0, sizeof(tty));
	cfsetispeed(&tty, B115200);
	cfsetospeed(&tty, B115200);
	tty.c_iflag &= ~(IGNBRK | BRKINT | ICRNL | INLCR | PARMRK | INPCK | ISTRIP | IXON);
    tty.c_oflag &= ~(OCRNL | ONLCR | ONLRET | ONOCR | OFILL | OPOST);
    tty.c_lflag &= ~(ECHO | ECHONL | ICANON | IEXTEN | ISIG);
    tty.c_cflag &= ~(CSIZE | PARENB);
    tty.c_cflag |= CS8;

	char pty[255];
	if(openpty(&radio_fd, &slave_pty, pty, &tty, nullptr) < 0) {
		flog::error("Failed to open PTY: {}", strerror(errno));
		std::exit(-1);
	}
	serial_port = pty;

	int flags = fcntl(radio_fd, F_GETFL, 0);
	fcntl(radio_fd, F_SETFL, flags | O_NONBLOCK | O_ASYNC);

	signal(SIGIO, rx_callback);
	if(fcntl(radio_fd, F_SETOWN, getpid()) < 0) {
		flog::error("Error setting sigio handler");
		std::exit(-1);
	}
	flog::info("Opened PTY {}", serial_port);
}

int main(int argc, char* argv[])
{
	open_pty();
	while(1);
}
