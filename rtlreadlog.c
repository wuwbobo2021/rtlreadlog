// alternative for RTL8762A, RTL8762C, RTL8763B and RTL8761ATT Log Debug Analyser on Linux
// by wuwbobo2021 <https://github.com/wuwbobo2021/rtlreadlog>, <wuwbobo@outlook.com>
// Licenced under GPL v3.0.

// last-modified date: 2023-10-03

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#include <libserialport.h>
typedef struct sp_port* SerialPort;

#define DEFAULT_BAUD 2000000

// see trace.h in BEE2 SDK

#define LOG_HEAD  0x7e
#define TYPE_BEE2 0x21

enum {
    SUBTYPE_DIRECT = 0x00,
    SUBTYPE_FORMAT = 0x10,
    SUBTYPE_BDADDR = 0x30,
    SUBTYPE_STRING = 0x40,
    SUBTYPE_BINARY = 0x50,
};

#define MODULE_APP 0x30

#define PARAM_BDADDR 0xbdbdbdbd
#define PARAM_STRING 0xdadadada
#define PARAM_BINARY 0xcdcdcdcd

#define PARAM_NUM_MAX 8

#pragma pack(push)
#pragma pack(1)

typedef struct {
	uint8_t  head;       // LOG_HEAD
	uint8_t  len;
	uint8_t  seq_num_1;
	uint8_t  padding;    // checksum? TODO: figure out how to calculate
	uint16_t seq_num_2;
	uint8_t  type;       // only care about TYPE_BEE2
	uint8_t  subtype;
	
	uint8_t  data[];     // not in LogHead
} LogHead;

typedef struct {
	uint8_t  module;     // only care about MODULE_APP
	uint16_t str_offset; // offset in the .trace file
	
	uint8_t  cnt_param;  // doesn't exist if no parameter is given
	uint8_t  padding;    // always 0x80 for TYPE_BEE2 SUBTYPE_FORMAT MODULE_APP. 128B?
	uint32_t params[];   // not in FormatHead
} FormatHead;

#pragma pack(pop)

#define LOG_DATA_LEN_MIN (sizeof(LogHead) + sizeof(FormatHead) - 1)

typedef struct {
	uint8_t  seq_num_1;
	uint16_t  seq_num_2;
	
	uint8_t cnt_param;
	uint32_t* p_params; //char data_params[0xff];
	char* p_str_format;
	
	uint8_t cnt_param_arr;
	struct param_arr {
		uint8_t type;
		uint8_t len;
		uint8_t data[0xff];
	} param_arrs[PARAM_NUM_MAX];
} LogItem; //used in this program

#ifdef _WIN32
	#include <windows.h>
	static inline void print_time_head() {
		SYSTEMTIME lt = {0};
		GetLocalTime(&lt);
		printf("%02d-%02d#%02d:%02d:%02d:%03d  ",
		       lt.wMonth, lt.wDay,
		       lt.wHour, lt.wMinute, lt.wSecond, lt.wMilliseconds);
	}
#else
	#include <time.h>
	#include <sys/time.h>
	static inline void print_time_head() {
		struct timeval tv;
		gettimeofday(&tv, NULL);
		struct tm* t = localtime(& tv.tv_sec);
		printf("%02d-%02d#%02d:%02d:%02d:%03d  ",
		       t->tm_mon + 1, t->tm_mday,
		       t->tm_hour, t->tm_min, t->tm_sec, (int)(tv.tv_usec/1000));
	}
#endif

static inline void print_line(const char* str) {puts(str);}
static inline void print_str(const char* str) {fputs(str, stdout);}
static inline void print_binary(void* buf, unsigned int cnt)
{
	if (! buf) return;
	for (uint8_t i = 0; i < cnt; i++)
		printf("%02x ", ((uint8_t*)buf)[i]);
}

static size_t get_file_size(const char* file_name)
{
	if (! file_name) return 0;
	FILE* fp = fopen(file_name, "rb");
	if (fp == NULL) return 0;

	fpos_t fpos; //current location
	fgetpos(fp, &fpos);
	
	fseek(fp, 0, SEEK_END);
	size_t n = ftell(fp);
	
	//fsetpos(fp, &fpos);
	fclose(fp); return n;
}

static void* load_file(const char* file_name)
{
	size_t file_size = get_file_size(file_name);
	if (! file_size) return NULL;

	char* data = malloc(file_size + 1);
	if (data == NULL) {
		print_line("Error: out of memory.");
		return NULL;
	}
	data[file_size] = 0x00;
	
	size_t read_size;
	FILE* fp = fopen(file_name, "r");
	read_size = fread(data, 1, file_size, fp);
	fclose(fp);
	
	if (read_size < file_size) {
		free(data); return NULL;
	}
	
	return data;
}

static SerialPort port_open(const char* port_name)
{
	SerialPort port;
	
	if (sp_get_port_by_name(port_name, &port) != SP_OK)
		return NULL;
	if (sp_open(port, SP_MODE_READ) != SP_OK)
		return NULL;
	
	sp_set_baudrate(port, DEFAULT_BAUD);
	sp_set_bits(port, 8);
	sp_set_parity(port, SP_PARITY_NONE);
	sp_set_stopbits(port, 1);
	sp_set_flowcontrol(port, SP_FLOWCONTROL_NONE);
	
	return port;
}

// exits the program when failed to read data
static inline void port_read(SerialPort port, void* buf, size_t count)
{
	enum sp_return result;
	result = sp_blocking_read(port, buf, count, 0xffffffff);
	
	if (result < 1) {
		print_line("Error: Read port failed.");
		exit(1);
	}
}

static inline int escape_format_len(const char* p_per)
{
	if (*p_per != '%') return 0;
	
	// flags to indicate items already passed
	bool mark = false, width = false, mark_len = false;
	
	unsigned int i = 1;
	while (true) {
		char ch = p_per[i];
		switch (ch) {
		// unfortunately floating point parameter isn't supported by log print
		case 'd': case 'i': case 'u': case 'o': case 'x': case 'X': case 'c': case 'p':
		case 's': case 'b': // %b is the only one not supported by C printf
			return i + 1; //valid format
		
		case '-': case '+': case '#': //case ' ':
			if (mark) return 0;
			break;
		case '0':
			if (width) return 0;
			break;
		case '1': case '2': case '3': case '4': case '5':
		case '6': case '7': case '8': case '9': case '*':
			if (mark_len) return 0;
			mark = true; //previous item will not be read anymore
			break;
		case 'l': case 'h':
			mark = width = mark_len = true; //previous items
			break;
		// note: '%%' is not printed as '%' but '%%' in DebugAnalyzer
		default: return 0; //including '\0'
		}
		i++;
	}
	return 0;
}

static void print_log_item(LogItem* log_item)
{
	print_time_head();
	printf("%03d  %05d   ", log_item->seq_num_1, log_item->seq_num_2);
	
	if (log_item->cnt_param == 0) {
		print_line(log_item->p_str_format); return;
	}
	
	unsigned int i_param = 0, i_param_arr = 0;
	char* p_str = log_item->p_str_format;
	char* p_per; char* p_per_prev = p_str - 1;
	while (true) {
		int flen = 0;
		while ((p_per = strchr(p_per_prev + 1, '%'))) { //found '%'
			flen = escape_format_len(p_per);
			p_per_prev = p_per;
			if (flen == 0) continue; else break;
		}
		if (!p_per || !flen || i_param >= log_item->cnt_param) {
			print_line(p_str); return;
		}

		if (p_per > p_str) {
			// Note: only one thread can write to the trace string data buffer
			*p_per = 0x00; print_str(p_str); *p_per = '%';
		}
		
		char ch = p_per[flen - 1]; char ch_tmp;
		uint32_t param_val = log_item->p_params[i_param];
		switch (ch) {
		case 'd': case 'i': case 'u': case 'o': case 'x': case 'X': case 'c':
			ch_tmp = p_per[flen]; p_per[flen] = 0x00;
			printf(p_per, param_val);
			p_per[flen] = ch_tmp; break;

		case 'p':
			printf("0x%08x", param_val); break; //for 32-bit chips

		case 's':
			if (i_param_arr >= log_item->cnt_param_arr) { //unlikely
				print_str("%s"); break;
			}
			if (param_val == PARAM_STRING)
				printf("%s", log_item->param_arrs[i_param_arr].data);
			else if (param_val == PARAM_BDADDR) {
				uint8_t* p = log_item->param_arrs[i_param_arr].data;
				printf("%02X:%02X:%02X:%02X:%02X:%02X",
					   p[5], p[4], p[3], p[2], p[1], p[0]);
			} else
				print_str("???Data Type Mismatch???"); //unlikely
			i_param_arr++; break;

		case 'b':
			if (i_param_arr >= log_item->cnt_param_arr) { //unlikely
				print_str("%b"); break;
			}
			if (param_val == PARAM_BINARY)
				print_binary(log_item->param_arrs[i_param_arr].data,
				             log_item->param_arrs[i_param_arr].len);
			else
				print_str("???Data Type Mismatch???"); //unlikely
			i_param_arr++; break;

		default: break;
		}
		i_param++;
		p_str = p_per + flen;
	}
}

SerialPort port;
char* trace_data = NULL; size_t len_trace_data;

static void read_loop()
{
	/*static*/ LogItem log_item; //large object
	log_item.cnt_param_arr = 0;
	
	uint8_t buf[0xff] = {0}; uint8_t len;
	LogHead* head = (LogHead*)buf;
	
	while (true) {
		port_read(port, &buf[0], 1);
		if (buf[0] != LOG_HEAD) continue;
		port_read(port, &buf[1], 1);
		len = buf[1]; if (! len) continue;
		port_read(port, &buf[2], len - 2);
		
		#if DEBUG
			print_binary(buf, len); print_str("\n");
		#endif
		
		if (head->type != TYPE_BEE2) continue;
		
		switch (head->subtype) {
		case SUBTYPE_BDADDR: case SUBTYPE_STRING: case SUBTYPE_BINARY:
			if (log_item.cnt_param_arr == PARAM_NUM_MAX || len <= sizeof(LogHead))
				break; //unlikely
			
			// load an array parameter into LogItem
			struct param_arr* p_param = & log_item.param_arrs[log_item.cnt_param_arr];
			p_param->type = head->subtype;
			p_param->len = len - sizeof(LogHead);
			memcpy(p_param->data, head->data, p_param->len);

			log_item.cnt_param_arr++; break;
			
		case SUBTYPE_FORMAT:
			if (len < LOG_DATA_LEN_MIN)
				goto clear_log_item;

			FormatHead* format = (FormatHead*)(head->data);
			if (format->module != MODULE_APP || format->str_offset >= len_trace_data)
				goto clear_log_item;

			// finish LogItem
			log_item.seq_num_1 = head->seq_num_1;
			log_item.seq_num_2 = head->seq_num_2;

			if (len == LOG_DATA_LEN_MIN) //without cnt_param
				log_item.cnt_param = 0;
			else {
				uint8_t len_data = len - sizeof(LogHead) - sizeof(FormatHead);
				if (len_data / 4 >= format->cnt_param)
					log_item.cnt_param = format->cnt_param;
				else
					log_item.cnt_param = len_data / 4;
				
				// this data is not copied, not designed for multi-thread processing
				if (len_data) log_item.p_params = format->params;
			}
			
			log_item.p_str_format = trace_data + format->str_offset;
			print_log_item(&log_item);

			clear_log_item:
			log_item.cnt_param_arr = 0; break;
			
		default: break;
		}
	}
	
}

void exit_handler()
{
	if (port) sp_close(port);
	if (trace_data) free(trace_data);
}
void signal_handler(int signal)
{
	//#if __STDC_VERSION__ >= 201112L
	//	quick_exit(0);
	//#else
		exit(0); //unsafe?
	//#endif
}

static void register_signals()
{
	atexit(&exit_handler);
	//#if __STDC_VERSION__ >= 201112L
	//	at_quick_exit(&exit_handler); //requires UCRT on Windows
	//#endif
	signal(SIGTERM, &signal_handler);
	signal(SIGINT, &signal_handler);
}

int main(int argc, char** argv)
{
	if (argc < 2) {
		print_line("Usage: rtlreadlog <port> <trace file>");
		return -1;
	}
	
	port = port_open(argv[1]);
	if (! port) {
		printf("Error: Cannot open serial port \"%s\".\n", argv[1]);
		return 1;
	}
	
	trace_data = load_file(argv[2]);
	if (! trace_data) {
		printf("Error: Cannot open trace file \"%s\".\n", argv[2]);
		return 1;
	}
	len_trace_data = get_file_size(argv[2]);

	register_signals();
	read_loop();
	return 0;
}