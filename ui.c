#include <curses.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "all.h"
#include "udx_conntrack.h"
int history_divs[HISTORY_DIVISIONS] = {1, 5, 20};

#define UNIT_DIVISIONS 4
char *unit_bits[UNIT_DIVISIONS] = {"b", "kb", "Mb", "Gb"};
char *unit_bytes[UNIT_DIVISIONS] = {"B", "kB", "MB", "GB"};

extern int history_pos;
extern int history_len;
extern sig_atomic_t signum;
extern int nstreams;
int dontshowdisplay = 0;
extern history_t history_totals;
line_t totals;

int peaksent;
int peakrecv;
int peaktotal;

void ui_curses_init() {
    initscr();
    keypad(stdscr, true);
    nonl();
    cbreak();
    noecho();
    halfdelay(2);
}

int stream_compare_bw(const void *_a, const void *_b /* compare sent */) {
    const udx_stream_t *a = _a;
    const udx_stream_t *b = _b;
    for (int i = 0; i < HISTORY_DIVISIONS; i++) {
        int64_t a_total = a->line.sent[i] + a->line.recv[i];
        int64_t b_total = b->line.sent[i] + b->line.recv[i];
        if (a_total != b_total) {
            return a_total < b_total ? -1 : 1;
        }
    }

    return 1;
}

extern option_t options;
void ui_init() {
    char msg[20];
    ui_curses_init();

    erase();

    snprintf(msg, 20, "listening on %s", options.interface);
    // showhelp(msg);
}
int history_length(int d) {
    if (history_len < history_divs[d])
        return history_len * RESOLUTION;
    else
        return history_divs[d] * RESOLUTION;
}

void calculate_totals() {

    for (int i = 0; i < HISTORY_LENGTH; i++) {
        int ii = (HISTORY_LENGTH + history_pos - i) % HISTORY_LENGTH;

        for (int j = 0; j < HISTORY_DIVISIONS; j++) {

            if (i < history_divs[j]) {
                totals.recv[j] += history_totals.recv[ii];
                totals.sent[j] += history_totals.sent[ii];
            }
        }
        if (history_totals.recv[i] > peakrecv) {
            peakrecv = history_totals.recv[i];
        }
        if (history_totals.sent[i] > peaksent) {
            peaksent = history_totals.sent[i];
        }
        if (history_totals.sent[i] + history_totals.recv[i] > peaktotal) {
            peaktotal = history_totals.sent[i] + history_totals.recv[i];
        }
    }
    for (int i = 0; i < HISTORY_DIVISIONS; i++) {
        int t = history_length(i);
        totals.recv[i] /= t;
        totals.sent[i] /= t;
    }
}

void analyze_data() {

    memset(&totals, 0, sizeof(totals));
    peaksent = 0;
    peakrecv = 0;
    peaktotal = 0;

    for (int i = 0; i < nstreams; i++) {
        udx_stream_t *s = stream_table[i];
        for (int j = 0; j < HISTORY_LENGTH; j++) {
            int k;
            int jj = (HISTORY_LENGTH + history_pos - i) % HISTORY_LENGTH;

            for (k = 0; k < HISTORY_DIVISIONS; k++) {
                if (j < history_divs[k]) {
                    s->line.sent[k] += s->history.sent[jj];
                    s->line.recv[k] += s->history.recv[jj];
                }
            }
        }

        for (int k = 0; k < HISTORY_DIVISIONS; k++) {
            s->line.sent[k] /= history_length(k);
            s->line.recv[k] /= history_length(k);
        }
    }

    qsort(stream_table, nstreams, sizeof(stream_table[0]), stream_compare_bw);

    calculate_totals();
}

void readable_size(float n, char *buf, int bsize, int ksize, bool bytes) {
    int i = 0;
    float size = 1;

    if (!bytes) {
        n *= 8;
    }
    while (1) {
        if (n < size * 1000 || i >= UNIT_DIVISIONS - 1) {
            snprintf(buf, bsize, " %4.0f%s", n / size, bytes ? unit_bytes[i] : unit_bits[i]);
            break;
        }
        i++;
        size *= ksize;
        if (n < size * 10) {
            snprintf(buf, bsize, " %4.2f%s", n / size, bytes ? unit_bytes[i] : unit_bits[i]);
            break;
        } else if (n < size * 100) {
            snprintf(buf, bsize, " %4.1f%s", n / size, bytes ? unit_bytes[i] : unit_bits[i]);
            break;
        }
    }
}

// static int get_bar_interval(float bandwidth) {
//     int i = 10;
//     if (bandwidth > 100000000) {
//         i = 100;
//     }
//     return i;
// }

static struct {
    int max;
    int interval;
} scale[] = {
    {64000, 10}, /* 64 kbit/s */
    {128000, 10},
    {256000, 10},
    {1000000, 10}, /* 1 Mbit/s */
    {10000000, 10},
    {100000000, 100},
    {1000000000, 100} /* 1 Gbit/s */
};
static int rateidx = 0;
static int rateidx_init = 0;
static bool wantbiggerrate;

static float get_max_bandwidth() {

    float max = scale[rateidx].max;

    return max;
}

static int get_bar_length(const int rate) {
    float l;
    if (rate <= 0) {
        return 0;
    }

    if (rate > scale[rateidx].max) {
        wantbiggerrate = true;
        if (!rateidx_init) {
            while (rate > scale[rateidx_init++].max) {
            }
            rateidx = rateidx_init;
        }
    }
    l = rate / get_max_bandwidth();

    return (l * COLS);
}

static void draw_bar_scale(int *y) {
    float i;
    float max = get_max_bandwidth();
    // float interval = get_bar_interval(max);

    // if showbars...

    float stop;
    move(*y, 0);
    clrtoeol();
    mvhline(*y + 1, 0, 0, COLS);

    // if (options.log_scale) {
    //     i = 1.25;
    //     stop = max / 8;
    // } else {
    i = max / (5 * 8);
    stop = max / 8;
    //}

    while (i <= stop) {
        char s[40];
        char *p;
        int x;
        readable_size(i, s, sizeof(s), 1000, false);
        p = s + strspn(s, " ");
        x = get_bar_length(i * 8);
        mvaddch(*y + 1, x, ACS_BTEE);
        if (x + strlen(p) > COLS) {
            x = COLS - strlen(p);
        }
        mvaddstr(*y, x, p);

        // if (options.log_scale) {
        //     i *= interval;
        // } else {
        i += max / (5 * 8);
        // }
    }
    mvaddch(*y + 1, 0, ACS_LLCORNER);
    *y += 2;
}

#define HOSTNAME_LENGTH 256

void sprint_flow(char *line, udx_flow_t *flow, int L) {

    char host[HOSTNAME_LENGTH - 24]; //
    char port[10];
    char id[12];

    struct sockaddr *sa = (struct sockaddr *)&flow->dst;
    getnameinfo(sa, addr_sizeof(sa), host, sizeof(host), port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);

    // int left = strlen(host);

    snprintf(id, sizeof(id), " %u", flow->id);

    // sprintf(line, "%-*s", L, host);
    // if (left > (L - strlen(port))) {
    //     left = L - strlen(port);
    //     if (left < 0) {
    //         left = 0;
    //     }
    // }

    // sprintf(line + left, "%-*s", L - left, port);

    // if (left > (L - strlen(id))) {
    //     left = L - strlen(id);
    //     if (left < 0) {
    //         left = 0;
    //     }
    // }

    snprintf(line, HOSTNAME_LENGTH, "%s:%s %u", host, port, flow->id);
}

void draw_bar(float n, int y) {
    int L;
    mvchgat(y, 0, -1, A_NORMAL, 0, NULL);
    L = get_bar_length(8 * n);
    if (L > 0) {
        mvchgat(y, 0, L + 1, A_REVERSE, 0, NULL);
    }
}

void draw_line_total(float sent, float recv, int y, int x) {
    char buf[10];
    readable_size(sent, buf, 10, 1024, 1);
    mvaddstr(y, x, buf);
    readable_size(recv, buf, 10, 1024, 1);
    mvaddstr(y + 1, x, buf);
}

void draw_line_totals(int y, line_t *line) {
    int j;
    int x = (COLS - 8 * HISTORY_DIVISIONS);

    for (j = 0; j < HISTORY_DIVISIONS; j++) {
        draw_line_total(line->sent[j], line->recv[j], y, x);
        x += 8;
    }

    draw_bar(line->sent[1], y);
    draw_bar(line->recv[1], y + 1);
}

void draw_totals(line_t *totals) {
    int y = LINES - 4;
    int j;
    char buf[10];
    int x = (COLS - 8 * HISTORY_DIVISIONS);
    y++;
    draw_line_totals(y, totals);
    y += 2;
    for (j = 0; j < HISTORY_DIVISIONS; j++) {
        readable_size((totals->sent[j] + totals->recv[j]), buf, 10, 1024, 0);
        mvaddstr(y, x, buf);
        x += 8;
    }
}

void ui_print() {

    char host1[HOSTNAME_LENGTH];
    char host2[HOSTNAME_LENGTH];

    static char *line;
    static int lcols;
    int y = 0;

    if (dontshowdisplay) {
        return;
    }

    if (!line || lcols != COLS) {
        free(line);
        line = calloc(COLS + 1, 1);
    }

    erase();

    draw_bar_scale(&y);

    // if (options.showhelp) {
    //     mvaddstr(y,0,HELP_MESSAGE);
    // } else {

    // int i = options.screen_offset < nstreams ? options.screen_offset : nstreams;
    int i = 0;

    while ((y < LINES - 5) && i < nstreams) {
        int x = 0;
        int L;
        udx_stream_t *s = stream_table[i++];

        if (y < LINES - 5) {
            L = (COLS - 8 * HISTORY_DIVISIONS - 4) / 2;
            // if (options.show_totals) {
            //     L -= 4;
            // }
            if (L > HOSTNAME_LENGTH) {
                L = HOSTNAME_LENGTH;
            }

            sprint_flow(host1, &s->flow[0], L);
            sprint_flow(host2, &s->flow[1], L);

            mvaddstr(y, x, host1);
            x += L;

            mvaddstr(y, x, " => ");
            mvaddstr(y + 1, x, " <= ");

            x += 4;
            mvaddstr(y, x, host2);
            // todo: show totals

            draw_line_totals(y, &s->line);
        }
        y += 2;
    }

    y = LINES - 3;
    mvhline(y - 1, 0, 0, COLS);
    mvaddstr(y, 0, "TX: ");
    mvaddstr(y + 1, 0, "RX: ");
    mvaddstr(y + 2, 0, "TOTAL: ");

    mvaddstr(y, 16, "cum: ");
    readable_size(history_totals.total_sent, line, 10, 1024, 1);
    mvaddstr(y, 22, line);

    readable_size(history_totals.total_recv, line, 10, 1024, 1);
    mvaddstr(y + 1, 22, line);

    readable_size(history_totals.total_recv + history_totals.total_sent, line, 10, 1024, 1);
    mvaddstr(y + 2, 22, line);

    /* peak traffic */
    mvaddstr(y, 32, "peak: ");

    readable_size(peaksent / RESOLUTION, line, 10, 1024, 0);
    mvaddstr(y, 39, line);

    readable_size(peakrecv / RESOLUTION, line, 10, 1024, 0);
    mvaddstr(y + 1, 39, line);

    readable_size(peaktotal / RESOLUTION, line, 10, 1024, 0);
    mvaddstr(y + 2, 39, line);

    mvaddstr(y, COLS - 8 * HISTORY_DIVISIONS - 8, "rates:");

    // draw totals
    draw_totals(&totals);

    // if (showhelphint) {
    //     mvaddstr(0, 0, " ");
    //     mvaddstr(0, 1, helpmsg);
    //     mvaddstr(0, 1 + strlen(helpmsg), " ");
    //     mvchgat(0, 0, strlen(helpmsg) + 2, A_REVERSE, 0, NULL);
    // }
    move(LINES - 1, COLS - 1);

    refresh();

    /* Bar chart auto scale */
    if (wantbiggerrate) {
        ++rateidx;
        wantbiggerrate = 0;
    }
}

void ui_tick(int print) {
    if (print) {
        ui_print();
    } /* else if (show_help_hint && (time(NULL) - helptimer > HELP_TIME) && !persistent_help) {
         show_help_hint = false;
         ui_print();
     }*/
}

void ui_loop() {
    char *edline(int linenum, char *prompt, char *initial);
    char *set_filter_code(char *filter);

    while (signum == 0) {
        int i;
        i = getch();
        switch (i) {
        case 'q':
            signum = 1;
            break;
        }
        tick(0);
    }
}

void ui_finish() {
    endwin();
}
