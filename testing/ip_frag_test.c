#include "ip.h"
#include "net.h"
#include "testing/log.h"
#include "utils.h"

#include <string.h>

extern FILE *control_flow;
extern FILE *arp_fout;

FILE *open_file(char *path, char *name, char *mode);

buf_t buf;
int main(int argc, char *argv[]) {
    FILE *in = open_file(argv[1], "in.txt", "r");
    control_flow = open_file(argv[1], "log", "w");
    if (in == 0 || control_flow == 0) {
        if (in)
            fclose(in);
        if (control_flow)
            fclose(control_flow);
        return -1;
    }
    arp_fout = control_flow;
    uint8_t *p = buf.payload + 1000;
    buf.data = p;
    buf.len = 0;
    char c;
    while (fread(&c, 1, 1, in)) {
        *p = c;
        p++;
        buf.len++;
    }
    PRINT_INFO("Feeding input.\n");
    ip_out(&buf, net_if_ip, NET_PROTOCOL_TCP);

    fclose(in);
    fclose(control_flow);

    FILE *demo = open_file(argv[1], "demo_log", "r");
    FILE *log = open_file(argv[1], "log", "r");
    int line = 1;
    int column = 0;
    int diff = 0;
    char c1, c2;
    PRINT_INFO("Comparing logs.\n");
    while (fread(&c1, 1, 1, demo)) {
        column++;
        if (fread(&c2, 1, 1, log) <= 0) {
            PRINT_WARN("Log file shorter than expected.\n");
            diff = 1;
            break;
        }
        if (c1 != c2) {
            PRINT_WARN("Different char found at line %d column %d.\n", line, column);
            diff = 1;
            break;
        }
        if (c1 == '\n') {
            line++;
            column = 0;
        }
    }
    if (diff == 0 && fread(&c2, 1, 1, log) == 1) {
        PRINT_WARN("Log file longer than expected.\n");
        diff = 1;
    }
    if (diff == 0) {
        PRINT_PASS("Log file check passed\n");
    }
    fclose(log);
    fclose(demo);
    return diff ? -1 : 0;
}
