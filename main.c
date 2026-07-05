#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <ctype.h>
#include <time.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

// where wpa_supplicant puts its control socket
#define CTRL_SOCK_DIR "/run/wpa_supplicant"
// max networks we can store
#define MAX_NETWORKS  128
// max networks to show on screen
#define MAX_SHOW      7
// max length of ssid
#define SSID_MAX      33
// max length of flags string
#define FLAGS_MAX     160
// buffer size for replies from wpa_supplicant
#define REPLY_BUF     8192
// version number
#define VERSION       "1.0.0"

// security types we support
enum {
    SEC_OPEN = 0,
    SEC_WEP,
    SEC_WPA_PSK,
    SEC_WPA3_SAE,
    SEC_WPA_MIXED,
    SEC_EAP
};

// actions the user can take
typedef enum { ACT_AGAIN, ACT_RESCAN, ACT_QUIT, ACT_CONNECTED } action_t;

// holds info about one wifi network
typedef struct {
    char bssid[18];      // mac address of access point
    int  frequency;      // frequency in mhz
    int  signal;         // signal strength in dbm
    char flags[FLAGS_MAX]; // wpa_supplicant flags
    char ssid[SSID_MAX];  // network name
    int  security;       // what kind of security
} network_t;

// connection to wpa_supplicant
typedef struct {
    int  fd;             // socket file descriptor
    char local_path[108]; // our local socket path
} wpa_ctrl_t;

// globals
static int use_color = 0;          // should we use colors?
static wpa_ctrl_t *g_ctrl = NULL;  // global control connection
static char g_iface[IF_NAMESIZE] = ""; // interface we're using

// color macros - empty if no color
#define CLR_RESET  (use_color ? "\x1b[0m"  : "")
#define CLR_BOLD   (use_color ? "\x1b[1m"  : "")
#define CLR_GREEN  (use_color ? "\x1b[32m" : "")
#define CLR_YELLOW (use_color ? "\x1b[33m" : "")
#define CLR_RED    (use_color ? "\x1b[31m" : "")
#define CLR_CYAN   (use_color ? "\x1b[36m" : "")
#define CLR_BLUE   (use_color ? "\x1b[34m" : "")

// forward declarations
static wpa_ctrl_t *wpa_ctrl_open(const char *path);
static void        wpa_ctrl_close(wpa_ctrl_t *ctrl);
static int         wpa_ctrl_request(wpa_ctrl_t *ctrl, const char *cmd, char *reply, size_t reply_len);
static void        send_cmd(wpa_ctrl_t *ctrl, const char *cmd);
static int         wait_for_event(wpa_ctrl_t *ctrl, const char *event, int timeout_sec);

static int find_wireless_interfaces(char ifaces[][IF_NAMESIZE], int max);
static int ensure_wpa_supplicant_running(const char *iface);

static int         parse_scan_line(char *line, network_t *net);
static int         determine_security(const char *flags);
static const char *security_to_str(int sec);
static int         scan_networks(wpa_ctrl_t *ctrl, network_t *out, int max);
static int         cmp_signal_desc(const void *a, const void *b);
static void        display_networks(network_t *nets, int n);

static void strip_newline(char *s);
static void read_password(char *buf, size_t bufsize);
static int  password_valid_for(int sec, const char *pw);
static int  is_hex_string(const char *s);
static void escape_quotes(const char *in, char *out, size_t outsize);

static int  configure_network(wpa_ctrl_t *ctrl, network_t *net, const char *password);
static void remove_network(wpa_ctrl_t *ctrl, int net_id);
static int  wait_for_connection_result(wpa_ctrl_t *ctrl, int timeout_sec);
static void save_config(wpa_ctrl_t *ctrl);
static action_t handle_selection(wpa_ctrl_t *ctrl, network_t *nets, int show_n, const char *iface);

static int  command_exists(const char *cmd);
static int  run_child(const char *path, char *const argv[]);
static void bring_interface_up(const char *iface);
static int  run_dhcp(const char *iface);
static void print_ip_info(const char *iface);
static void ensure_rfkill_unblocked(void);
static void show_wifi_status(const char *iface);
static void check_dependencies(void);
static void ensure_root_or_sudo(void);

static void handle_sigint(int sig);
static void print_banner(void);
static void print_usage(void);
static void print_version(void);

// open connection to wpa_supplicant control socket
static wpa_ctrl_t *wpa_ctrl_open(const char *path) {
    wpa_ctrl_t *ctrl = calloc(1, sizeof(*ctrl));
    if (!ctrl) return NULL;

    // create a socket
    ctrl->fd = socket(PF_UNIX, SOCK_DGRAM, 0);
    if (ctrl->fd < 0) { free(ctrl); return NULL; }

    // bind to a local socket
    struct sockaddr_un local;
    memset(&local, 0, sizeof(local));
    local.sun_family = AF_UNIX;
    snprintf(local.sun_path, sizeof(local.sun_path), "/tmp/wific_%d", (int)getpid());
    unlink(local.sun_path);

    if (bind(ctrl->fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
        close(ctrl->fd);
        free(ctrl);
        return NULL;
    }
    strncpy(ctrl->local_path, local.sun_path, sizeof(ctrl->local_path) - 1);

    // connect to wpa_supplicant
    struct sockaddr_un remote;
    memset(&remote, 0, sizeof(remote));
    remote.sun_family = AF_UNIX;
    strncpy(remote.sun_path, path, sizeof(remote.sun_path) - 1);

    if (connect(ctrl->fd, (struct sockaddr *)&remote, sizeof(remote)) < 0) {
        close(ctrl->fd);
        unlink(ctrl->local_path);
        free(ctrl);
        return NULL;
    }

    return ctrl;
}

// close connection and clean up
static void wpa_ctrl_close(wpa_ctrl_t *ctrl) {
    if (!ctrl) return;
    close(ctrl->fd);
    unlink(ctrl->local_path);
    free(ctrl);
}

// send command and wait for reply
static int wpa_ctrl_request(wpa_ctrl_t *ctrl, const char *cmd, char *reply, size_t reply_len) {
    if (send(ctrl->fd, cmd, strlen(cmd), 0) < 0) return -1;

    // wait for reply, skip event messages that start with '<'
    time_t start = time(NULL);
    while (time(NULL) - start < 10) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(ctrl->fd, &rfds);
        struct timeval tv = {2, 0};
        int r = select(ctrl->fd + 1, &rfds, NULL, NULL, &tv);
        if (r <= 0) return -1;

        ssize_t n = recv(ctrl->fd, reply, reply_len - 1, 0);
        if (n < 0) return -1;
        reply[n] = '\0';

        if (n > 0 && reply[0] == '<') continue; // it's an event, skip it
        return 0;
    }
    return -1;
}

// send command, ignore reply
static void send_cmd(wpa_ctrl_t *ctrl, const char *cmd) {
    char reply[256];
    wpa_ctrl_request(ctrl, cmd, reply, sizeof(reply));
}

// wait for specific event from wpa_supplicant
static int wait_for_event(wpa_ctrl_t *ctrl, const char *event, int timeout_sec) {
    time_t start = time(NULL);
    char buf[4096];
    while (time(NULL) - start < timeout_sec) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(ctrl->fd, &rfds);
        struct timeval tv = {1, 0};
        int r = select(ctrl->fd + 1, &rfds, NULL, NULL, &tv);
        if (r > 0) {
            ssize_t n = recv(ctrl->fd, buf, sizeof(buf) - 1, 0);
            if (n > 0) {
                buf[n] = '\0';
                if (strstr(buf, event)) return 0;
            }
        }
    }
    return -1;
}

// find wireless interfaces by checking /sys/class/net/*/wireless
static int find_wireless_interfaces(char ifaces[][IF_NAMESIZE], int max) {
    DIR *d = opendir("/sys/class/net");
    if (!d) return 0;
    int count = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL && count < max) {
        if (ent->d_name[0] == '.') continue;
        char path[300];
        snprintf(path, sizeof(path), "/sys/class/net/%s/wireless", ent->d_name);
        struct stat st;
        if (stat(path, &st) == 0) {
            strncpy(ifaces[count], ent->d_name, IF_NAMESIZE - 1);
            ifaces[count][IF_NAMESIZE - 1] = '\0';
            count++;
        }
    }
    closedir(d);
    return count;
}

// make sure wpa_supplicant is running, start it if needed
static int ensure_wpa_supplicant_running(const char *iface) {
    char sock_path[256];
    snprintf(sock_path, sizeof(sock_path), "%s/%s", CTRL_SOCK_DIR, iface);

    struct stat st;
    if (stat(sock_path, &st) == 0) return 0; // already running

    printf("  Starting wpa_supplicant...\n");

    // look for existing config file
    const char *candidates[] = {
        "/etc/wpa_supplicant/wpa_supplicant.conf",
        "/etc/wpa_supplicant.conf",
        NULL
    };
    const char *conf_path = NULL;
    for (int i = 0; candidates[i]; i++) {
        if (access(candidates[i], R_OK) == 0) { conf_path = candidates[i]; break; }
    }

    // if no config, create a temporary one
    char tmp_conf[] = "/tmp/wific_conf_XXXXXX";
    if (!conf_path) {
        int fd = mkstemp(tmp_conf);
        if (fd < 0) { perror("mkstemp"); return -1; }
        const char *def = "ctrl_interface=" CTRL_SOCK_DIR "\nupdate_config=1\n";
        ssize_t w = write(fd, def, strlen(def));
        close(fd);
        if (w < 0) return -1;
        conf_path = tmp_conf;
    }

    // use driver from env or default to nl80211
    const char *driver = getenv("WIFIC_DRIVER");
    if (!driver) driver = "nl80211";

    // fork and start wpa_supplicant
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return -1; }
    if (pid == 0) {
        execlp("wpa_supplicant", "wpa_supplicant", "-B", "-i", iface,
               "-c", conf_path, "-D", driver, (char *)NULL);
        _exit(127);
    }

    int status = 0;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "%s[FAIL] Could not start wpa_supplicant%s\n", CLR_RED, CLR_RESET);
        fprintf(stderr, "  Install with: sudo apt install wpasupplicant\n");
        return -1;
    }

    // wait for socket to appear
    for (int i = 0; i < 30; i++) {
        if (stat(sock_path, &st) == 0) return 0;
        usleep(100000);
    }

    fprintf(stderr, "%s[FAIL] wpa_supplicant started but no control socket found%s\n", CLR_RED, CLR_RESET);
    return -1;
}

// figure out what security type from flags
static int determine_security(const char *flags) {
    if (strstr(flags, "EAP")) return SEC_EAP;
    int has_sae = strstr(flags, "SAE") != NULL;
    int has_psk = strstr(flags, "PSK") != NULL;
    int has_wep = strstr(flags, "WEP") != NULL;
    if (has_sae && has_psk) return SEC_WPA_MIXED;
    if (has_sae) return SEC_WPA3_SAE;
    if (has_psk) return SEC_WPA_PSK;
    if (has_wep) return SEC_WEP;
    return SEC_OPEN;
}

// convert security type to string
static const char *security_to_str(int sec) {
    switch (sec) {
        case SEC_OPEN:      return "Open";
        case SEC_WEP:       return "WEP";
        case SEC_WPA_PSK:   return "WPA/WPA2";
        case SEC_WPA3_SAE:  return "WPA3";
        case SEC_WPA_MIXED: return "WPA2/3";
        case SEC_EAP:       return "Enterprise";
        default:            return "?";
    }
}

// parse one line from scan results
static int parse_scan_line(char *line, network_t *net) {
    char *p = line;
    char *fields[4];
    for (int i = 0; i < 4; i++) {
        char *tab = strchr(p, '\t');
        if (!tab) return -1;
        *tab = '\0';
        fields[i] = p;
        p = tab + 1;
    }
    memset(net, 0, sizeof(*net));
    strncpy(net->bssid, fields[0], sizeof(net->bssid) - 1);
    net->bssid[sizeof(net->bssid) - 1] = '\0';
    net->frequency = atoi(fields[1]);
    net->signal    = atoi(fields[2]);
    strncpy(net->flags, fields[3], sizeof(net->flags) - 1);
    net->flags[sizeof(net->flags) - 1] = '\0';
    strncpy(net->ssid, p, sizeof(net->ssid) - 1);
    net->ssid[sizeof(net->ssid) - 1] = '\0';
    return 0;
}

// scan for networks and return list
static int scan_networks(wpa_ctrl_t *ctrl, network_t *out, int max) {
    char reply[REPLY_BUF];

    // tell wpa_supplicant to scan
    if (wpa_ctrl_request(ctrl, "SCAN", reply, sizeof(reply)) < 0) return -1;
    wait_for_event(ctrl, "CTRL-EVENT-SCAN-RESULTS", 15);

    // get scan results
    if (wpa_ctrl_request(ctrl, "SCAN_RESULTS", reply, sizeof(reply)) < 0) return -1;

    int count = 0;
    char *saveptr = NULL;
    char *line = strtok_r(reply, "\n", &saveptr);
    line = strtok_r(NULL, "\n", &saveptr); // skip header

    // parse each line
    while (line && count < max) {
        network_t net;
        if (parse_scan_line(line, &net) == 0 && net.ssid[0] != '\0') {
            net.security = determine_security(net.flags);

            // deduplicate - keep strongest signal per ssid
            int dup = -1;
            for (int i = 0; i < count; i++) {
                if (strcmp(out[i].ssid, net.ssid) == 0) { dup = i; break; }
            }
            if (dup >= 0) {
                if (net.signal > out[dup].signal) out[dup] = net;
            } else {
                out[count++] = net;
            }
        }
        line = strtok_r(NULL, "\n", &saveptr);
    }
    return count;
}

// compare signals for sorting (strongest first)
static int cmp_signal_desc(const void *a, const void *b) {
    const network_t *na = (const network_t *)a;
    const network_t *nb = (const network_t *)b;
    return nb->signal - na->signal;
}

// show networks to user
static void display_networks(network_t *nets, int n) {
    printf("\n  %s%-2s %-30s %-14s %-10s %-6s%s\n", 
           CLR_BOLD, "#", "SSID", "SIGNAL", "SECURITY", "BAND", CLR_RESET);
    printf("  %s-- %-30s %-14s %-10s %-6s%s\n", 
           CLR_BOLD, "----", "------", "--------", "----", CLR_RESET);
    
    for (int i = 0; i < n; i++) {
        // convert dbm to quality percentage
        int q = 2 * (nets[i].signal + 100);
        if (q > 100) q = 100;
        if (q < 0) q = 0;

        // make a signal bar
        char bar[11];
        int filled = q / 10;
        for (int j = 0; j < 10; j++) bar[j] = (j < filled) ? '#' : '-';
        bar[10] = '\0';

        // pick color based on quality
        const char *color = (q >= 67) ? CLR_GREEN : (q >= 34 ? CLR_YELLOW : CLR_RED);
        const char *band  = (nets[i].frequency < 3000) ? "2.4G" :
                             (nets[i].frequency >= 5955 ? "6G" : "5G");

        char sigcell[24];
        snprintf(sigcell, sizeof(sigcell), "%s[%s]%s %3d%%", color, bar, CLR_RESET, q);

        printf("  %-2d %-30.30s %-14s %-10s %-6s\n",
               i + 1, nets[i].ssid, sigcell,
               security_to_str(nets[i].security), band);
    }
    printf("\n");
}

// remove newline from string
static void strip_newline(char *s) {
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r')) {
        s[--len] = '\0';
    }
}

// read password without echoing to terminal
static void read_password(char *buf, size_t bufsize) {
    struct termios oldt, newt;
    int have_tty = isatty(STDIN_FILENO);

    if (have_tty) {
        tcgetattr(STDIN_FILENO, &oldt);
        newt = oldt;
        newt.c_lflag &= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    }

    printf("  Password: ");
    fflush(stdout);
    if (!fgets(buf, bufsize, stdin)) buf[0] = '\0';
    strip_newline(buf);

    if (have_tty) {
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        printf("\n");
    }
}

// check if string is hex
static int is_hex_string(const char *s) {
    if (!*s) return 0;
    for (size_t i = 0; s[i]; i++) {
        if (!isxdigit((unsigned char)s[i])) return 0;
    }
    return 1;
}

// check if password is valid for security type
static int password_valid_for(int sec, const char *pw) {
    size_t len = strlen(pw);
    switch (sec) {
        case SEC_WPA_PSK:
        case SEC_WPA3_SAE:
        case SEC_WPA_MIXED:
            return len >= 8 && len <= 63;
        case SEC_WEP:
            return len == 5 || len == 13 || len == 10 || len == 26;
        default:
            return 1;
    }
}

// escape quotes and backslashes
static void escape_quotes(const char *in, char *out, size_t outsize) {
    size_t j = 0;
    for (size_t i = 0; in[i] && j + 2 < outsize; i++) {
        if (in[i] == '"' || in[i] == '\\') out[j++] = '\\';
        out[j++] = in[i];
    }
    out[j] = '\0';
}

// configure network in wpa_supplicant
static int configure_network(wpa_ctrl_t *ctrl, network_t *net, const char *password) {
    char cmd[600], reply[64], esc[256];

    // add new network
    if (wpa_ctrl_request(ctrl, "ADD_NETWORK", reply, sizeof(reply)) < 0) return -1;
    if (strncmp(reply, "FAIL", 4) == 0) return -1;
    int net_id = atoi(reply);
    if (net_id < 0) return -1;

    // set ssid
    escape_quotes(net->ssid, esc, sizeof(esc));
    snprintf(cmd, sizeof(cmd), "SET_NETWORK %d ssid \"%s\"", net_id, esc);
    send_cmd(ctrl, cmd);

    // set security based on type
    switch (net->security) {
    case SEC_OPEN:
        snprintf(cmd, sizeof(cmd), "SET_NETWORK %d key_mgmt NONE", net_id);
        send_cmd(ctrl, cmd);
        break;

    case SEC_WEP:
        snprintf(cmd, sizeof(cmd), "SET_NETWORK %d key_mgmt NONE", net_id);
        send_cmd(ctrl, cmd);
        if (is_hex_string(password) && (strlen(password) == 10 || strlen(password) == 26)) {
            snprintf(cmd, sizeof(cmd), "SET_NETWORK %d wep_key0 %s", net_id, password);
        } else {
            escape_quotes(password, esc, sizeof(esc));
            snprintf(cmd, sizeof(cmd), "SET_NETWORK %d wep_key0 \"%s\"", net_id, esc);
        }
        send_cmd(ctrl, cmd);
        snprintf(cmd, sizeof(cmd), "SET_NETWORK %d auth_alg OPEN SHARED", net_id);
        send_cmd(ctrl, cmd);
        break;

    case SEC_WPA_PSK:
        snprintf(cmd, sizeof(cmd), "SET_NETWORK %d key_mgmt WPA-PSK", net_id);
        send_cmd(ctrl, cmd);
        escape_quotes(password, esc, sizeof(esc));
        snprintf(cmd, sizeof(cmd), "SET_NETWORK %d psk \"%s\"", net_id, esc);
        send_cmd(ctrl, cmd);
        break;

    case SEC_WPA3_SAE:
        snprintf(cmd, sizeof(cmd), "SET_NETWORK %d key_mgmt SAE", net_id);
        send_cmd(ctrl, cmd);
        snprintf(cmd, sizeof(cmd), "SET_NETWORK %d ieee80211w 2", net_id);
        send_cmd(ctrl, cmd);
        escape_quotes(password, esc, sizeof(esc));
        snprintf(cmd, sizeof(cmd), "SET_NETWORK %d psk \"%s\"", net_id, esc);
        send_cmd(ctrl, cmd);
        break;

    case SEC_WPA_MIXED:
        snprintf(cmd, sizeof(cmd), "SET_NETWORK %d key_mgmt WPA-PSK SAE", net_id);
        send_cmd(ctrl, cmd);
        snprintf(cmd, sizeof(cmd), "SET_NETWORK %d ieee80211w 1", net_id);
        send_cmd(ctrl, cmd);
        escape_quotes(password, esc, sizeof(esc));
        snprintf(cmd, sizeof(cmd), "SET_NETWORK %d psk \"%s\"", net_id, esc);
        send_cmd(ctrl, cmd);
        break;

    default:
        break;
    }

    // enable and select the network
    snprintf(cmd, sizeof(cmd), "ENABLE_NETWORK %d", net_id);
    send_cmd(ctrl, cmd);
    snprintf(cmd, sizeof(cmd), "SELECT_NETWORK %d", net_id);
    send_cmd(ctrl, cmd);

    return net_id;
}

// remove network from wpa_supplicant
static void remove_network(wpa_ctrl_t *ctrl, int net_id) {
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "REMOVE_NETWORK %d", net_id);
    send_cmd(ctrl, cmd);
}

// wait for connection result, return 0 for success, -2 for wrong password, -1 for timeout
static int wait_for_connection_result(wpa_ctrl_t *ctrl, int timeout_sec) {
    time_t start = time(NULL);
    char buf[4096];

    while (time(NULL) - start < timeout_sec) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(ctrl->fd, &rfds);
        struct timeval tv = {1, 0};
        int r = select(ctrl->fd + 1, &rfds, NULL, NULL, &tv);
        if (r > 0) {
            ssize_t n = recv(ctrl->fd, buf, sizeof(buf) - 1, 0);
            if (n > 0) {
                buf[n] = '\0';
                if (strstr(buf, "CTRL-EVENT-CONNECTED")) return 0;
                if (strstr(buf, "CTRL-EVENT-SSID-TEMP-DISABLED") && strstr(buf, "WRONG_KEY"))
                    return -2;
            }
        } else {
            printf(".");
            fflush(stdout);
        }
    }
    return -1;
}

// save config to disk
static void save_config(wpa_ctrl_t *ctrl) {
    send_cmd(ctrl, "SAVE_CONFIG");
}

// handle user selection
static action_t handle_selection(wpa_ctrl_t *ctrl, network_t *nets, int show_n, const char *iface) {
    display_networks(nets, show_n);
    printf("  Select [%s1-%d%s, %sr%s=rescan, %sq%s=quit]: ", 
           CLR_BOLD, show_n, CLR_RESET, CLR_BOLD, CLR_RESET, CLR_BOLD, CLR_RESET);

    char line[32];
    if (!fgets(line, sizeof(line), stdin)) return ACT_QUIT;
    strip_newline(line);

    if (line[0] == 'q' || line[0] == 'Q') return ACT_QUIT;
    if (line[0] == 'r' || line[0] == 'R') return ACT_RESCAN;

    int idx = atoi(line) - 1;
    if (idx < 0 || idx >= show_n) {
        printf("  %sInvalid selection%s\n\n", CLR_RED, CLR_RESET);
        return ACT_AGAIN;
    }

    network_t *sel = &nets[idx];

    // enterprise not supported
    if (sel->security == SEC_EAP) {
        printf("\n  %s'%s'%s is an enterprise network - not supported\n\n",
               CLR_YELLOW, sel->ssid, CLR_RESET);
        return ACT_AGAIN;
    }

    // get password if needed
    char password[128] = "";
    if (sel->security != SEC_OPEN) {
        while (1) {
            read_password(password, sizeof(password));
            if (password[0] == '\0') {
                printf("  Cancelled.\n\n");
                return ACT_AGAIN;
            }
            if (password_valid_for(sel->security, password)) break;
            printf("  %sInvalid key for %s%s\n", CLR_RED, security_to_str(sel->security), CLR_RESET);
            printf("  WPA: 8-63 chars, WEP: 5/13 chars or 10/26 hex\n\n");
        }
    }

    printf("\n  Connecting to %s", sel->ssid);
    fflush(stdout);

    // configure and connect
    int net_id = configure_network(ctrl, sel, password);
    if (net_id < 0) {
        printf("\n  %sFailed to configure network%s\n\n", CLR_RED, CLR_RESET);
        return ACT_AGAIN;
    }

    int result = wait_for_connection_result(ctrl, 20);
    printf("\n");

    if (result == 0) {
        printf("  %s[OK] Connected to %s%s\n", CLR_GREEN, sel->ssid, CLR_RESET);
        bring_interface_up(iface);
        run_dhcp(iface);
        print_ip_info(iface);
        save_config(ctrl);
        return ACT_CONNECTED;
    }
    if (result == -2) {
        printf("  %s[FAIL] Wrong password for %s%s\n\n", CLR_RED, sel->ssid, CLR_RESET);
        remove_network(ctrl, net_id);
        return ACT_AGAIN;
    }
    printf("  %s[FAIL] Timed out connecting to %s%s\n\n", CLR_RED, sel->ssid, CLR_RESET);
    remove_network(ctrl, net_id);
    return ACT_AGAIN;
}

// check if command exists in path
static int command_exists(const char *cmd) {
    const char *path = getenv("PATH");
    if (!path) path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

    char pathbuf[2048];
    strncpy(pathbuf, path, sizeof(pathbuf) - 1);
    pathbuf[sizeof(pathbuf) - 1] = '\0';

    char *saveptr = NULL;
    char *dir = strtok_r(pathbuf, ":", &saveptr);
    while (dir) {
        char full[1024];
        snprintf(full, sizeof(full), "%s/%s", dir, cmd);
        if (access(full, X_OK) == 0) return 1;
        dir = strtok_r(NULL, ":", &saveptr);
    }
    return 0;
}

// run child process
static int run_child(const char *path, char *const argv[]) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        execvp(path, argv);
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

// bring interface up
static void bring_interface_up(const char *iface) {
    char *argv[] = {"ip", "link", "set", (char *)iface, "up", NULL};
    run_child("ip", argv);
}

// run dhcp client
static int run_dhcp(const char *iface) {
    if (command_exists("dhcpcd")) {
        char *argv[] = {"dhcpcd", "-n", (char *)iface, NULL};
        printf("  DHCP: dhcpcd\n");
        return run_child("dhcpcd", argv);
    }
    if (command_exists("dhclient")) {
        char *argv[] = {"dhclient", "-1", (char *)iface, NULL};
        printf("  DHCP: dhclient\n");
        return run_child("dhclient", argv);
    }
    if (command_exists("udhcpc")) {
        char *argv[] = {"udhcpc", "-i", (char *)iface, "-n", "-q", NULL};
        printf("  DHCP: udhcpc\n");
        return run_child("udhcpc", argv);
    }
    printf("  %s[WARN] No DHCP client found - install dhcpcd%s\n", CLR_YELLOW, CLR_RESET);
    return -1;
}

// show ip address
static void print_ip_info(const char *iface) {
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) return;

    int found = 0;
    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        if (strcmp(ifa->ifa_name, iface) != 0) continue;
        
        if (ifa->ifa_addr->sa_family == AF_INET) {
            char ip[INET_ADDRSTRLEN];
            struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
            inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof(ip));
            printf("  %sIP:%s %s\n", CLR_GREEN, CLR_RESET, ip);
            found = 1;
        }
    }
    if (!found) {
        printf("  %s[WARN] No IPv4 address%s\n", CLR_YELLOW, CLR_RESET);
    }
    freeifaddrs(ifaddr);
}

// unblock wifi with rfkill
static void ensure_rfkill_unblocked(void) {
    if (command_exists("rfkill")) {
        char *argv[] = {"rfkill", "unblock", "wifi", NULL};
        run_child("rfkill", argv);
    }
}

// show interface status
static void show_wifi_status(const char *iface) {
    char path[256];
    snprintf(path, sizeof(path), "/sys/class/net/%s/operstate", iface);
    FILE *f = fopen(path, "r");
    if (f) {
        char state[32];
        if (fgets(state, sizeof(state), f)) {
            strip_newline(state);
            const char *color = (strcmp(state, "up") == 0) ? CLR_GREEN : CLR_YELLOW;
            printf("  Interface: %s%s%s\n", color, iface, CLR_RESET);
            printf("  State: %s%s%s\n", color, state, CLR_RESET);
        }
        fclose(f);
    }
}

// check if required commands exist
static void check_dependencies(void) {
    if (!command_exists("wpa_supplicant")) {
        fprintf(stderr, "\n%s[ERROR] wpa_supplicant not found%s\n", CLR_RED, CLR_RESET);
        fprintf(stderr, "  Install with:\n");
        fprintf(stderr, "    Debian/Ubuntu: sudo apt install wpasupplicant\n");
        fprintf(stderr, "    Arch:         sudo pacman -S wpa_supplicant\n");
        fprintf(stderr, "    Fedora:       sudo dnf install wpa_supplicant\n\n");
        exit(1);
    }
}

// make sure we're root
static void ensure_root_or_sudo(void) {
    if (geteuid() != 0) {
        fprintf(stderr, "%s[ERROR] Need root privileges%s\n", CLR_YELLOW, CLR_RESET);
        fprintf(stderr, "  Re-run with: sudo wific\n\n");
        exit(1);
    }
}

// handle ctrl+c
static void handle_sigint(int sig) {
    (void)sig;
    if (g_ctrl) {
        send_cmd(g_ctrl, "DETACH");
        close(g_ctrl->fd);
        unlink(g_ctrl->local_path);
    }
    printf("\n\n  %sInterrupted%s\n", CLR_YELLOW, CLR_RESET);
    _exit(1);
}

// show banner
static void print_banner(void) {
    printf("\n");
    printf("  %s+--------------------------------------+%s\n", CLR_CYAN, CLR_RESET);
    printf("  %s|  %swific%s - One-Command WiFi Connector  %s|%s\n", 
           CLR_CYAN, CLR_BOLD, CLR_RESET, CLR_CYAN, CLR_RESET);
    printf("  %s+--------------------------------------+%s\n", CLR_CYAN, CLR_RESET);
    printf("\n");
}

// show usage
static void print_usage(void) {
    printf("\n%s wific %s - One-Command WiFi Connector v%s\n\n", CLR_BOLD, CLR_RESET, VERSION);
    printf("Usage: wific [OPTIONS]\n\n");
    printf("OPTIONS:\n");
    printf("  -h, --help     Show this help\n");
    printf("  -v, --version  Show version\n");
    printf("  -i IFACE       Use specific interface\n\n");
    printf("ENVIRONMENT:\n");
    printf("  WIFIC_IFACE    Interface to use\n");
    printf("  WIFIC_DRIVER   wpa_supplicant driver (default: nl80211)\n\n");
    printf("EXAMPLES:\n");
    printf("  wific           # Auto-detect and connect\n");
    printf("  wific -i wlan0  # Use specific interface\n");
    printf("  sudo wific      # Run as root\n\n");
}

// show version
static void print_version(void) {
    printf("wific version %s\n", VERSION);
    printf("One-Command WiFi Connector for Linux\n");
}

// main program
int main(int argc, char **argv) {
    use_color = isatty(STDOUT_FILENO);

    // parse arguments
    const char *specified_iface = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage();
            return 0;
        }
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
            print_version();
            return 0;
        }
        if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            specified_iface = argv[++i];
        }
    }

    // check deps and root
    check_dependencies();
    ensure_root_or_sudo();

    // find interface
    const char *env_iface = getenv("WIFIC_IFACE");
    if (specified_iface) {
        strncpy(g_iface, specified_iface, sizeof(g_iface) - 1);
    } else if (env_iface) {
        strncpy(g_iface, env_iface, sizeof(g_iface) - 1);
    } else {
        char ifaces[8][IF_NAMESIZE];
        int cnt = find_wireless_interfaces(ifaces, 8);
        if (cnt == 0) {
            fprintf(stderr, "%s[ERROR] No wireless interface found%s\n", CLR_RED, CLR_RESET);
            fprintf(stderr, "  Make sure your WiFi adapter is connected.\n");
            return 1;
        } else if (cnt == 1) {
            strncpy(g_iface, ifaces[0], sizeof(g_iface) - 1);
        } else {
            printf("Multiple wireless interfaces found:\n");
            for (int i = 0; i < cnt; i++) printf("  %d) %s\n", i + 1, ifaces[i]);
            printf("Select [1-%d]: ", cnt);
            char line[16];
            if (!fgets(line, sizeof(line), stdin)) return 1;
            int idx = atoi(line) - 1;
            if (idx < 0 || idx >= cnt) idx = 0;
            strncpy(g_iface, ifaces[idx], sizeof(g_iface) - 1);
        }
    }
    g_iface[IF_NAMESIZE - 1] = '\0';

    // unblock wifi and start wpa_supplicant
    ensure_rfkill_unblocked();
    if (ensure_wpa_supplicant_running(g_iface) < 0) return 1;

    // connect to wpa_supplicant
    char sock_path[256];
    snprintf(sock_path, sizeof(sock_path), "%s/%s", CTRL_SOCK_DIR, g_iface);

    wpa_ctrl_t *ctrl = wpa_ctrl_open(sock_path);
    if (!ctrl) {
        fprintf(stderr, "%s[ERROR] Could not connect to wpa_supplicant at %s%s\n", 
                CLR_RED, sock_path, CLR_RESET);
        fprintf(stderr, "  Make sure NetworkManager/iwd aren't managing this interface.\n");
        fprintf(stderr, "  To disable: sudo nmcli device set %s managed no\n", g_iface);
        return 1;
    }
    g_ctrl = ctrl;
    signal(SIGINT, handle_sigint);
    send_cmd(ctrl, "ATTACH");

    // show banner and status
    print_banner();
    show_wifi_status(g_iface);

    // main loop
    int running = 1;
    while (running) {
        printf("  Scanning for networks...\n");
        network_t nets[MAX_NETWORKS];
        int n = scan_networks(ctrl, nets, MAX_NETWORKS);

        if (n <= 0) {
            printf("  No networks found. Press Enter to rescan, q to quit: ");
            char line[16];
            if (!fgets(line, sizeof(line), stdin) || line[0] == 'q' || line[0] == 'Q') break;
            continue;
        }

        qsort(nets, n, sizeof(network_t), cmp_signal_desc);
        int show_n = (n > MAX_SHOW) ? MAX_SHOW : n;

        for (;;) {
            action_t act = handle_selection(ctrl, nets, show_n, g_iface);
            if (act == ACT_AGAIN) continue;
            if (act == ACT_RESCAN) break;
            running = 0;
            break;
        }
    }

    // cleanup
    send_cmd(ctrl, "DETACH");
    wpa_ctrl_close(ctrl);
    
    if (running) {
        printf("\n  %sGoodbye!%s\n", CLR_BOLD, CLR_RESET);
    } else {
        printf("\n  %s[OK] Connected successfully!%s\n", CLR_GREEN, CLR_RESET);
        printf("  Press Ctrl+C to disconnect.\n");
    }
    return 0;
}
