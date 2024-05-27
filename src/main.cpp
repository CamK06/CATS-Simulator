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

void hexdump(uint8_t* data, size_t len)
{
	static char buf[255];
	int buf_idx = 0;
	for(int i = 0; i < len; i++) {
		if(i % 16 == 0 && i != 0) {
			flog::info(buf);
			std::memset(buf, 0x00, 255);
			buf_idx = 0;
		}
		sprintf(buf + buf_idx, "%02X ", data[i]);
		buf_idx += 3;
	}
}

void print_packet(cats_packet_t* pkt)
{
    cats_whisker_data_t* data;
	static char buf[8192];
    if(cats_packet_get_identification(pkt, (cats_ident_whisker_t**)&data) == CATS_SUCCESS) {
        sprintf(buf, "IDENT: \t%s-%d [ICON: %d]", 
                data->identification.callsign, 
                data->identification.ssid, 
                data->identification.icon
        );
		flog::info(buf);
    }
    if(cats_packet_get_route(pkt, (cats_route_whisker_t**)&data) == CATS_SUCCESS) {
        int written = sprintf(buf, "ROUTE: \t(MAX %d) ", data->route.max_digipeats);
        cats_route_hop_t* hop = &(data->route.hops);
        while(hop != NULL) {
            if(hop->hop_type == CATS_ROUTE_INET) {
                written += sprintf(buf + written, "[NET]");
            }
            else if(hop->hop_type == CATS_ROUTE_FUTURE) {
                written += sprintf(buf + written, "%s-%d*", hop->callsign, hop->ssid);
            }
            else if(hop->hop_type == CATS_ROUTE_PAST) {
                written += sprintf(buf + written, "%s-%d [%.1f dBm]", hop->callsign, hop->ssid, hop->rssi);
            }
            if(hop->next != NULL) {
                written += sprintf(buf + written, " -> ");
            }int written = 0;
            hop = hop->next;
        }
        flog::info(buf);
		written = 0;
    }
    char comment[CATS_MAX_PKT_LEN];
    if(cats_packet_get_comment(pkt, comment) == CATS_SUCCESS) {
        sprintf(buf, "CMNT: \t'%s'", comment);
		flog::info(buf);
    }
    if(cats_packet_get_gps(pkt, (cats_gps_whisker_t**)&data) == CATS_SUCCESS) {
        sprintf(buf, "GPS: \t(%.4f, %.4f) +/- %d m, v = %.2f m/s [N %.2f] deg",
                data->gps.latitude,
                data->gps.longitude,
                data->gps.max_error,
                data->gps.speed,
                data->gps.heading,
                data->gps.altitude
        );
		flog::info(buf);
		sprintf(buf, "ALT: \t%.2f m", data->gps.altitude);
		flog::info(buf);
    }
    if(cats_packet_get_nodeinfo(pkt, (cats_nodeinfo_whisker_t**)&data) == CATS_SUCCESS) {
        if(data->node_info.hardware_id.enabled && data->node_info.software_id.enabled) {
            sprintf(buf, "HW: \t0x%04x SW: 0x%02x", data->node_info.hardware_id.val, data->node_info.software_id.val);
			flog::info(buf);
        }
        else if(data->node_info.hardware_id.enabled) {
            sprintf(buf, "HW: \t0x%04x", data->node_info.hardware_id.val);
			flog::info(buf);
        }
        else if(data->node_info.software_id.enabled) {
            sprintf(buf, "SW: \t0x%02x", data->node_info.software_id.val);
			flog::info(buf);
        }

        if(data->node_info.uptime.enabled) {
            sprintf(buf, "UTIME: \t%d s", data->node_info.uptime.val);
			flog::info(buf);
        }
        if(data->node_info.ant_height.enabled) {
            sprintf(buf, "VERT: \t%d m", data->node_info.ant_height.val);
			flog::info(buf);
        }
        if(data->node_info.ant_gain.enabled) {
            sprintf(buf, "GAIN: \t%.2f dBi", data->node_info.ant_gain.val);
			flog::info(buf);
        }
        if(data->node_info.tx_power.enabled) {
            sprintf(buf, "TXP: \t%d dBm", data->node_info.tx_power.val);
			flog::info(buf);
        }
        if(data->node_info.voltage.enabled) {
            sprintf(buf, "VOLTS: \t%d V", data->node_info.voltage.val);
			flog::info(buf);
        }
        if(data->node_info.temperature.enabled) {
            sprintf(buf, "TEMP: \t%d C", data->node_info.temperature.val);
			flog::info(buf);
        }
    }
	cats_whisker_t** arbitrary;
	if((cats_packet_get_arbitrary(pkt, &arbitrary) != CATS_FAIL)
	&& arbitrary[0]->data.raw[0] == 0xc0) {
		flog::info("SRC: \tAPRS");
	}
	else {
		flog::info("SRC: \tCATS");
	}
}

void send_pkt(cats_packet_t* pkt)
{
	uint8_t buf[CATS_MAX_PKT_LEN];
	int len = cats_packet_semi_encode(pkt, buf);
	if(len == CATS_FAIL) {
		flog::error("Failed to encode packet");
		return;
	}
	len = cats_radio_iface_encode(buf, len, 0);
	
	if(write(radio_fd, buf, len) < 0) {
		flog::error("Failed to write to serial port");
	}
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
		hexdump(buffer, buf_ptr);
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

	flog::info("Serial RX:");
	hexdump(buffer, buf_ptr);
	printf("\n");

	cats_packet_t* pkt;
	cats_packet_prepare(&pkt);
	if(cats_packet_semi_decode(pkt, buffer, r) == CATS_FAIL) {
		flog::error("Failed to decode packet");
		memset(buffer, 0, CATS_MAX_PKT_LEN);
		buf_ptr = 0;
		cats_packet_destroy(&pkt);
		return;
	}

	flog::info("Decoded packet:");
	print_packet(pkt);	
	cats_packet_destroy(&pkt);
	memset(buffer, 0, CATS_MAX_PKT_LEN);
	buf_ptr = 0;
	printf("\n\n\n");
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
