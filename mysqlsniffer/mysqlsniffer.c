// mysqlsniffer.c Aug 18, 2006 UNSTABLE
/*
  mysqlsniffer.c - Watch MySQL traffic on a TCP/IP network
  v1.2 Aug 18, 2006 UNSTABLE

  Original source and more information at:
  http://hackmysql.com/mysqlsniffer

  Thanks to Ian Redfern for publishing "MySQL Protocol" at:
  http://www.redferni.uklinux.net/mysql/MySQL-Protocol.html.

  Thanks to The Tcpdump Group (http://tcpdump.org) for libpcap
  and sniffex.c which this program takes strongly from in main().

  Thanks to Jay Pipes for publishing the internals.texi in HTML at:
  http://www.jpipes.com/mysqldox/

  Thanks to Marek for helping me try to get this release stable.

  Official documentation of the MySQL protocol is available at:
  http://dev.mysql.com/doc/internals/en/client-server-protocol.html

  To compile: gcc -O2 -lpcap -o mysqlsniffer mysqlsniffer.c packet_handlers.c misc.c
*/

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <getopt.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "user_defines.h"
#include "mysql_defines.h"
#include "state_map.h"
#include "mysqlsniffer.h"
#include "sniff_headers.h"
#include "packet_handlers.h"
#include "misc.h"

/*
  Global vars
*/
u_char buff[SNAP_LEN];     // For general MySQL packet processing
u_char *buff_frag;         // Last pkt fragment (tag->frag) + next pkts
pcap_t *handle;
struct bpf_program fp;
char   filter_exp[11] = "port ";
u_int  total_mysql_pkts;
u_int  total_mysql_bytes;

/*
  Function protos
*/
// General 
void show_help(void);
void proc_ops(int argc, char *argv[]);
void handle_ctrl_c(int signo);
void handle_sighup(int signo);
void cleanup(void);
void print_stats(void);
void proc_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void init_state_map(void);

// MySQL packet processing
int multi_pkts(const u_char *pkts, u_int total_len);
int parse_pkt(u_char *pkt, u_int len);

// Connection tracking
void init_tags(void);
tag_id *get_tag(u_int addr, u_short port);
void free_tags(void);


/*
  Main code and general functions
*/
int main(int argc, char *argv[])
{
   char *dev = NULL;
   char errbuf[PCAP_ERRBUF_SIZE];
   bpf_u_int32 mask;
   bpf_u_int32 net;

   if (argc > 1) {
      proc_ops(argc, argv);

      dev = argv[optind];
      if(!dev) {
         printf("No network interface name given\n\n");
         show_help();
      }

      if(!op.port) {
         strcpy(filter_exp + 5, "3306");
         op.port_n = 3306;
      }
   }
   else
      show_help();

   if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
      printf("Couldn't get netmask for device %s: %s\n", dev, errbuf);
      net = mask = 0;
	}

   handle = pcap_open_live(dev, SNAP_LEN, 1, 0, errbuf);
   if(handle == NULL) {
      printf("Couldn't open device %s: %s\n", dev, errbuf);
      exit(-1);
   }

   if(pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
      printf("Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
      exit(-1);
   }

   if (pcap_setfilter(handle, &fp) == -1) {
      printf("Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
      exit(-1);
   }

   printf("mysqlsniffer listening for MySQL on interface %s %s\n", dev, filter_exp);

   signal(SIGINT, handle_ctrl_c);
   signal(SIGHUP, handle_sighup);

   init_tags();
   init_state_map();

   pcap_loop(handle, -1, proc_packet, NULL);

   printf("ERROR: pcap_loop returned from an infinite loop\n");

   cleanup();
   print_stats();

   exit(-1);
}

void show_help(void)
{
   printf("mysqlsniffer v1.2 - Watch MySQL traffic on a TCP/IP network\n\n");
   printf("Usage: mysqlsniffer [OPTIONS] INTERFACE\n\n");
   printf("OPTIONS:\n");
   printf("   --port N        Listen for MySQL on port number N (default 3306)\n");
   printf("   --verbose       Show extra packet information\n");
   printf("   --tcp-ctrl      Show TCP control packets (SYN, FIN, RST, ACK)\n");
   printf("   --net-hdrs      Show major IP and TCP header values\n");
   printf("   --no-mysql-hdrs Do not show MySQL header (packet ID and length)\n");
   printf("   --state         Show state\n");
   printf("   --v40           MySQL server is version 4.0\n");
   printf("   --dump          Dump all packets in hex\n");
   printf("   --help          Print this\n");
   printf("\nOriginal source code and more information at:\n   http://hackmysql.com/mysqlsniffer\n");

   exit(0);
}

void proc_ops(int argc, char *argv[])
{
   struct option ops[] = {
      {"port",          1,  NULL,  'p'},
      {"verbose",       0,  NULL,  'v'},
      {"tcp-ctrl",      0,  NULL,  't'},
      {"net-hdrs",      0,  NULL,  'n'},
      {"no-mysql-hdrs", 0,  NULL,  'm'},
      {"state",         0,  NULL,  's'},
      {"v40",           0,  NULL,  'o'},
      {"dump",          0,  NULL,  'd'},
      {"help",          0,  NULL,  'h'},
      {0,               0,     0,    0}
   };

   int o;

   while((o = getopt_long(argc, argv, "p:qvthsd", ops, NULL)) != -1) {
      switch(o) {
         case 'p': op.port = 1;
                   strncpy(filter_exp + 5, optarg, (strlen(optarg) < 6 ? strlen(optarg) : 5));
                   filter_exp[10] = 0;
                   op.port_n = atoi(optarg);
                                     break;
         case 'v': op.verbose = 1;   break;
         case 't': op.tcp_ctrl = 1;  break;
         case 'n': op.net_hdrs = 1;  break;
         case 'm': op.no_myhdrs = 1; break;
         case 's': op.state = 1;     break;
         case 'o': op.v40 = 1;       break;
         case 'd': op.dump = 1;      break;
         case 'h': show_help();
      }
   }
}

void handle_ctrl_c(int signo)
{
   cleanup();
   print_stats();

   exit(0);
}

void handle_sighup(int signo)
{
   print_stats();
   total_mysql_pkts = total_mysql_bytes = 0;
   free_tags();

   printf("Connection tracking has been reset\n");
}

void cleanup(void)
{
   pcap_freecode(&fp);
   pcap_close(handle);

   if(buff_frag) free(buff_frag);
   free_tags();
}

void print_stats(void)
{
   printf("%u MySQL packets captured (%u bytes)\n", total_mysql_pkts, total_mysql_bytes);
}

void proc_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
   char origin = 0;
   const struct sniff_ethernet *ethernet;
   const struct sniff_ip *ip;
   const struct sniff_tcp *tcp;
   const u_char *mysql;
   u_int size_ip;
   u_int size_tcp;
   u_int size_mysql;
   int retval = PKT_UNKNOWN_STATE;

   if(header->len > SNAP_LEN) {
      printf("Captured packet too large: %d bytes\n", header->len);
      printf("Max capture packet size: %d bytes\n", SNAP_LEN);
      return;
   }

   ethernet   = (struct sniff_ethernet*)(packet);
	ip         = (struct sniff_ip*)(packet + SIZE_ETHERNET);
   size_ip    = IP_HL(ip) * 4;
	tcp        = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
   size_tcp   = TH_OFF(tcp) * 4;
   mysql      = (packet + SIZE_ETHERNET + size_ip + size_tcp);
   size_mysql = ntohs(ip->ip_len) - size_ip - size_tcp;

   if(size_mysql > 0 || op.tcp_ctrl) {
      if(ntohs(tcp->th_sport) == op.port_n) {
         printf("server > %s.%d: ", inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));
         tag = get_tag((u_int)ip->ip_dst.s_addr, tcp->th_dport);
         if(!tag) {
            printf("Out of tracking tags; can't track any more connections.\n");
            return;
         }
         origin = ORIGIN_SERVER;
      }
      else {
         printf("%s.%d > server: ", inet_ntoa(ip->ip_src), ntohs(tcp->th_sport));
         tag = get_tag((u_int)ip->ip_src.s_addr, tcp->th_sport);
         if(!tag) {
            printf("Out of tracking tags; can't track any more connections.\n");
            return;
         }
         origin = ORIGIN_CLIENT;
      }

      if(op.net_hdrs)
         printf("(IP len %u id %u TCP seq %u ack %u) ", ntohs(ip->ip_len),
                                                        ntohs(ip->ip_id),
                                                        ntohl(tcp->th_seq),
                                                        ntohl(tcp->th_ack));
   }

   if(size_mysql == 0) {
      if(op.tcp_ctrl) {
         if(tcp->th_flags & TH_SYN) printf("SYN ");
         if(tcp->th_flags & TH_FIN) printf("FIN ");
         if(tcp->th_flags & TH_RST) printf("RST ");
         if(tcp->th_flags & TH_ACK) printf("ACK ");

         printf("\n");
      }
      return;
   }

   if(size_mysql > 4) {
      tag->current_origin = origin; // Set here so TCP ctrl msgs don't mess things up
      retval = multi_pkts(mysql, size_mysql);
   }
   else
      printf("MySQL packet is too small: %d bytes\n", size_mysql);

   if(retval == PKT_PARSED_OK)
      tag->last_origin = tag->current_origin;

   return;
}


/*
  MySQL packet processing
*/

/* 
  MySQL will send N amount of logical packets in one physical packet. Each
  logical packet starts with a MySQL header which says how long that logical
  pkt is minus the header itself (m->pkt_length). Along w/ the total length of
  captured MySQL data from libpcap (total_len), we can seperate all the logical
  pkts even though they all vary in length.
*/
int multi_pkts(const u_char *pkts, u_int total_len)
{
   int retval = PKT_UNKNOWN_STATE;
   u_int i = 0;
   u_int used_len = 0;
   struct mysql_hdr *m;

   // If last pkt was fragmented, merge with current pkts
   if(tag->pkt_fragment) {
      tag->pkt_fragment = 0;

      printf("\n\t::FRAGMENT START::\n\t");

      if(buff_frag)
         buff_frag = (u_char *)realloc(buff_frag, tag->frag_len + total_len);
      else
         buff_frag = (u_char *)malloc(tag->frag_len + total_len);
      memcpy(buff_frag, tag->frag, tag->frag_len);
      memcpy(buff_frag + tag->frag_len, pkts, total_len);

      pkts = buff_frag;
      total_len += tag->frag_len;
   }

   while(1) {
      m = (struct mysql_hdr *)pkts; // Packet header

      pkts += 4; // First data byte
      i    += 4;

      // Check if pkts > len of pkts actually received (last pkt is fragmented)
      used_len = used_len + m->pkt_length + 4;
      if(used_len > total_len) {
         tag->pkt_fragment = 1;
         tag->frag_len     = m->pkt_length - (used_len - total_len) + 4;

         pkts -= 4;

         if(tag->frag)
            tag->frag = (u_char *)realloc(tag->frag, tag->frag_len);
         else
            tag->frag = (u_char *)malloc(tag->frag_len);
         memcpy(tag->frag, pkts, tag->frag_len);

         printf("::FRAGMENT END::\n");

         retval = PKT_FRAGMENTED;
         break;
      }

      tag->current_pkt_id = m->pkt_id;

      if(!op.no_myhdrs) printf("ID %u len %u ", m->pkt_id, m->pkt_length);

      total_mysql_pkts++;
      total_mysql_bytes = total_mysql_bytes + 4 + m->pkt_length;

      if(m->pkt_length) {
         memcpy(buff, pkts, m->pkt_length);
         retval = parse_pkt(buff, m->pkt_length);
      }
      else
         printf("ID %u Zero-length MySQL packet ", m->pkt_id);
      printf("\n");

      tag->last_pkt_id = m->pkt_id;

      if((i + m->pkt_length) >= total_len) break; // No more pkts

      pkts += m->pkt_length; // Next pkt header
      i += m->pkt_length;

      if(retval == PKT_PARSED_OK)
         tag->last_origin = tag->current_origin;

      printf("\t");
   }

   return retval;
}

/*
  Parse one logical MySQL packet

  This function has 6 parts:
    1. Parse error pkts
    2. Handle no last origin
    3. Handle client re-sending pkt (set state back to STATE_SLEEP)
    4. Set state and number of possible events for state
    5. Try to handle pkt given state and possible events
    6. Check if pkt was handled/parsed ok

  If the pkt fails to be handled, something is broken or missing because
  when 6 fails, it goes to 2 which acts as a kind of catch-all.
  But if 2 then fails and we get back to 6 a second time, a warning
  is printed ("Client pkt has no valid handler") and the function returns
  a failure.
*/
int parse_pkt(u_char *pkt, u_int len)
{
   u_short state;
   u_short event;
   u_short num_events;
   u_short have_failed_before = 0;
   PKT_HANDLER ha = 0;

   if(op.dump) {
      dump_pkt(pkt, len, 1);
      return PKT_PARSED_OK;
   }

   if(*pkt == 0xFF) { // Error
      pkt_error(pkt, len);
      tag->state = STATE_SLEEP;
      return PKT_PARSED_OK;
   }

   /*
     If there is no last origin, this usually means this is the first pkt
     we're seeing for this connection. However, this pkt could then be
     anything, so we have to wait for a reliable starting point which is
     any client > server command because a client will only send a command
     from a state of sleep (i.e, after the server is done responding).
   */
   if(!tag->last_origin) {
DETERMINE_PKT:
      if(tag->current_origin == ORIGIN_SERVER) {

         ha = state_map[STATE_NOT_CONNECTED].ha[0]; // server handshake pkt?
         if((*ha)(pkt, len) == PKT_HANDLED) {
            tag->state = state_map[STATE_NOT_CONNECTED].next_state[0];
            return PKT_PARSED_OK;
         }
         else {
            /*
              We're in the middle of a pre-established connection or something
              weird happened like the server responding for no reason (perhaps
              the client sent a TCP re-xmit?)
            */
            printf("Waiting for server to finish response... ");
            dump_pkt(pkt, len, 0);
            tag->state = STATE_SLEEP; // Will be asleep when done
            tag->last_origin = 0;
            return PKT_UNKNOWN_STATE; // Keeps multi_pkts() from setting tag->last_origin
         }

      }
      else { // pkt from client

         /*
           Since the MySQL protocol is purely request-response, if a pkt is from
           the client it must mean MySQL has finished responding and is asleep
           waiting for further commands.
         */
         tag->state = STATE_SLEEP;

         // Special cases
         if(len == 1) {
            if(*pkt == COM_STATISTICS) tag->state = STATE_ONE_STRING;
         }

      }
   }

   // Client re-sent pkt (MySQL probably didn't respond to the first pkt)
   if(tag->last_origin == ORIGIN_CLIENT &&
      tag->current_origin == ORIGIN_CLIENT &&
      tag->state != STATE_SLEEP)
   {
      printf("::RETRANSMIT:: ");
      tag->state = STATE_SLEEP;
   }

   // Safeguard
   if(tag->current_origin == ORIGIN_CLIENT &&
      tag->current_pkt_id == 0 &&
      tag->state != STATE_SLEEP)
   {
      tag->state = STATE_SLEEP;
   }

   state = tag->state; // Current state
   num_events = state_map[state].num_events; // Number of possible events for current state
   if(op.state) printf("state '%s' ", state_name[state]);

   // Try to handle the pkt...
   if(num_events == 1) {
      tag->event = state_map[state].event[0];
      ha = state_map[state].ha[0];

      if((*ha)(pkt, len))
         tag->state = state_map[state].next_state[0]; // pkt was handled
      else
         ha = 0;
   }
   else {
      for(event = 0; event < num_events; event++) {
         tag->event = state_map[state].event[event];
         ha = state_map[state].ha[event];

         if((*ha)(pkt, len)) {
            // pkt was handled
            tag->state = state_map[state].next_state[event];
            break;
         }
         else ha = 0;
      }
   }

   // ...Check if pkt was handled
   if(!ha) {
      printf("::Unhandled Event:: ");

      if(!have_failed_before) {
         have_failed_before = 1; // Prevent infinite loop
         goto DETERMINE_PKT;
      }
      else {
         printf("Client pkt has no valid handler ");
         dump_pkt(pkt, len, 1);
         return PKT_UNKNOWN_STATE;
      }
   }

   return PKT_PARSED_OK;
}

/*
  Connection tracking

  The following functions provides the means by which mysqlsniffer maintains
  information about the current state of each MySQL connection (identified by
  unique client IP-port pairs). Along with the psuedo state transition table
  we're less in the dark about what kind of data we're dealing with.
*/

void init_tags(void)
{
   int i;

   for(i = 0; i < MAX_TAGS; i++)
      tags[i].state = STATE_NOT_CONNECTED;
}

tag_id *get_tag(u_int addr, u_short port)
{
   int i;
   int last_i = -1;

   for(i = 0; i < MAX_TAGS; i++) {
      if(!tags[i].id_address) {
         if(last_i == -1) last_i = i;
         continue;
      }
      if(tags[i].id_address == addr && tags[i].id_port == port) return (tag_id *)&tags[i];
   }

   if(last_i >= 0) {
         tags[last_i].id_address = addr;
         tags[last_i].id_port = port;
         return (tag_id *)&tags[last_i];
   }

   return 0;
}

void remove_tag(tag_id *tag)
{
   if(!tag) return;

   // printf(" (Removing tag %u.%u) ", tag->id_address, tag->id_port);

   tag->id_address = 0;
   tag->id_port    = 0;

   tag->current_origin = 0;
   tag->current_pkt_id = 0;
   tag->last_origin    = 0;
   tag->last_pkt_id    = 0;
   tag->state          = STATE_NOT_CONNECTED;
}

void free_tags(void)
{
   int i;

   for(i = 0; i < MAX_TAGS; i++) {
      if(tags[i].frag)   free(tags[i].frag);
      if(tags[i].fields) free(tags[i].fields);

      tags[i].id_address = 0;
      tags[i].id_port    = 0;

      tags[i].current_origin = 0;
      tags[i].current_pkt_id = 0;
      tags[i].last_origin    = 0;
      tags[i].last_pkt_id    = 0;
      tags[i].state          = STATE_NOT_CONNECTED;

      tags[i].frag   = 0;
      tags[i].fields = 0;
   }
}

void init_state_map(void)
{
   state_map[STATE_ONE_STRING].ha[0] = &pkt_string;
   state_map[STATE_ONE_STRING].event[0] = EVENT_ONE_STRING;
   state_map[STATE_ONE_STRING].next_state[0] = STATE_SLEEP;
   state_map[STATE_ONE_STRING].num_events = 1;

   state_map[STATE_OK].ha[0] = &pkt_ok;
   state_map[STATE_OK].event[0] = EVENT_OK;
   state_map[STATE_OK].next_state[0] = STATE_SLEEP;
   state_map[STATE_OK].num_events = 1;

   state_map[STATE_FIELD_LIST].ha[0] = &pkt_field;
   state_map[STATE_FIELD_LIST].event[0] = EVENT_FL_FIELD;
   state_map[STATE_FIELD_LIST].next_state[0] = STATE_FIELD_LIST;
   state_map[STATE_FIELD_LIST].ha[1] = &pkt_end;
   state_map[STATE_FIELD_LIST].event[1] = EVENT_END;
   state_map[STATE_FIELD_LIST].next_state[1] = STATE_SLEEP;
   state_map[STATE_FIELD_LIST].num_events = 2;

   state_map[STATE_SLEEP].ha[0] = &pkt_com_x_string;
   state_map[STATE_SLEEP].event[0] = COM_QUERY;
   state_map[STATE_SLEEP].next_state[0] = STATE_TXT_RS;
   state_map[STATE_SLEEP].ha[1] = &pkt_com_x_string;
   state_map[STATE_SLEEP].event[1] = COM_INIT_DB;
   state_map[STATE_SLEEP].next_state[1] = STATE_OK;
   state_map[STATE_SLEEP].ha[2] = &pkt_com_x_string;
   state_map[STATE_SLEEP].event[2] = COM_FIELD_LIST;
   state_map[STATE_SLEEP].next_state[2] = STATE_FIELD_LIST;
   state_map[STATE_SLEEP].ha[3] = &pkt_com_x_string;
   state_map[STATE_SLEEP].event[3] = COM_CREATE_DB;
   state_map[STATE_SLEEP].next_state[3] = STATE_OK;
   state_map[STATE_SLEEP].ha[4] = &pkt_com_x_string;
   state_map[STATE_SLEEP].event[4] = COM_DROP_DB;
   state_map[STATE_SLEEP].next_state[4] = STATE_OK;
   state_map[STATE_SLEEP].ha[5] = &pkt_com_x_int;
   state_map[STATE_SLEEP].event[5] = COM_PROCESS_KILL;
   state_map[STATE_SLEEP].next_state[5] = STATE_OK;
   state_map[STATE_SLEEP].ha[6] = &pkt_com_x_int;
   state_map[STATE_SLEEP].event[6] = COM_REFRESH;
   state_map[STATE_SLEEP].next_state[6] = STATE_OK;
   state_map[STATE_SLEEP].ha[7] = &pkt_end;
   state_map[STATE_SLEEP].event[7] = COM_SHUTDOWN;
   state_map[STATE_SLEEP].next_state[7] = STATE_END;
   state_map[STATE_SLEEP].ha[8] = &pkt_com_x;
   state_map[STATE_SLEEP].event[8] = COM_DEBUG;
   state_map[STATE_SLEEP].next_state[8] = STATE_END;
   state_map[STATE_SLEEP].ha[9] = &pkt_com_x;
   state_map[STATE_SLEEP].event[9] = COM_STATISTICS;
   state_map[STATE_SLEEP].next_state[9] = STATE_ONE_STRING;
   state_map[STATE_SLEEP].ha[10] = &pkt_com_x;
   state_map[STATE_SLEEP].event[10] = COM_PING;
   state_map[STATE_SLEEP].next_state[10] = STATE_COM_PONG;
   state_map[STATE_SLEEP].ha[11] = &pkt_com_x;
   state_map[STATE_SLEEP].event[11] = COM_QUIT;
   state_map[STATE_SLEEP].next_state[11] = STATE_NOT_CONNECTED;
   state_map[STATE_SLEEP].ha[12] = &pkt_com_x_string;
   state_map[STATE_SLEEP].event[12] = COM_STMT_PREPARE;
   state_map[STATE_SLEEP].next_state[12] = STATE_STMT_META;
   state_map[STATE_SLEEP].ha[13] = &pkt_stmt_execute;
   state_map[STATE_SLEEP].event[13] = COM_STMT_EXECUTE;
   state_map[STATE_SLEEP].next_state[13] = STATE_BIN_RS;
   state_map[STATE_SLEEP].ha[14] = &pkt_com_x_int;
   state_map[STATE_SLEEP].event[14] = COM_STMT_CLOSE;
   state_map[STATE_SLEEP].next_state[14] = STATE_SLEEP;
   state_map[STATE_SLEEP].num_events = 15;

   state_map[STATE_STMT_META].ha[0] = &pkt_stmt_meta;
   state_map[STATE_STMT_META].event[0] = EVENT_STMT_META;
   state_map[STATE_STMT_META].next_state[0] = STATE_STMT_PARAM;
   state_map[STATE_STMT_META].num_events = 1;

   state_map[STATE_STMT_PARAM].ha[0] = &pkt_field;
   state_map[STATE_STMT_PARAM].event[0] = EVENT_STMT_PARAM;
   state_map[STATE_STMT_PARAM].next_state[0] = STATE_STMT_PARAM;
   state_map[STATE_STMT_PARAM].ha[1] = &pkt_end;
   state_map[STATE_STMT_PARAM].event[1] = EVENT_END;
   state_map[STATE_STMT_PARAM].next_state[1] = STATE_FIELD_LIST;
   state_map[STATE_STMT_PARAM].num_events = 2;

   state_map[STATE_FIELD].ha[0] = &pkt_field;
   state_map[STATE_FIELD].event[0] = EVENT_FIELD ;
   state_map[STATE_FIELD].next_state[0] = STATE_FIELD;
   state_map[STATE_FIELD].ha[1] = &pkt_end;
   state_map[STATE_FIELD].event[1] = EVENT_END;
   state_map[STATE_FIELD].next_state[1] = STATE_TXT_ROW;
   state_map[STATE_FIELD].num_events = 2;

   state_map[STATE_FIELD_BIN].ha[0] = &pkt_field;
   state_map[STATE_FIELD_BIN].event[0] = EVENT_FIELD_BIN;
   state_map[STATE_FIELD_BIN].next_state[0] = STATE_FIELD_BIN;
   state_map[STATE_FIELD_BIN].ha[1] = &pkt_end;
   state_map[STATE_FIELD_BIN].event[1] = EVENT_END;
   state_map[STATE_FIELD_BIN].next_state[1] = STATE_BIN_ROW;
   state_map[STATE_FIELD_BIN].num_events = 2;

   state_map[STATE_TXT_RS].ha[0] = &pkt_n_fields;
   state_map[STATE_TXT_RS].event[0] = EVENT_NUM_FIELDS;
   state_map[STATE_TXT_RS].next_state[0] = STATE_FIELD;
   state_map[STATE_TXT_RS].ha[1] = &pkt_ok;
   state_map[STATE_TXT_RS].event[1] = EVENT_OK;
   state_map[STATE_TXT_RS].next_state[1] = STATE_SLEEP;
   state_map[STATE_TXT_RS].num_events = 2;

   state_map[STATE_BIN_RS].ha[0] = &pkt_n_fields;
   state_map[STATE_BIN_RS].event[0] = EVENT_NUM_FIELDS_BIN;
   state_map[STATE_BIN_RS].next_state[0] = STATE_FIELD_BIN;
   state_map[STATE_BIN_RS].ha[1] = &pkt_ok;
   state_map[STATE_BIN_RS].event[1] = EVENT_OK;
   state_map[STATE_BIN_RS].next_state[1] = STATE_SLEEP;
   state_map[STATE_BIN_RS].num_events = 2;

   state_map[STATE_END].ha[0] = &pkt_end;
   state_map[STATE_END].event[0] = EVENT_END;
   state_map[STATE_END].next_state[0] = STATE_SLEEP;
   state_map[STATE_END].num_events = 1;

   state_map[STATE_ERROR].ha[0] = &pkt_error;
   state_map[STATE_ERROR].event[0] = EVENT_ERROR;
   state_map[STATE_ERROR].next_state[0] = STATE_SLEEP;
   state_map[STATE_ERROR].num_events = 1;

   state_map[STATE_TXT_ROW].ha[0] = &pkt_row;
   state_map[STATE_TXT_ROW].event[0] = EVENT_ROW;
   state_map[STATE_TXT_ROW].next_state[0] = STATE_TXT_ROW;
   state_map[STATE_TXT_ROW].ha[1] = &pkt_ok;
   state_map[STATE_TXT_ROW].event[1] = EVENT_OK;
   state_map[STATE_TXT_ROW].next_state[1] = STATE_TXT_ROW;
   state_map[STATE_TXT_ROW].ha[2] = &pkt_end;
   state_map[STATE_TXT_ROW].event[2] = EVENT_END;
   state_map[STATE_TXT_ROW].next_state[2] = STATE_SLEEP;
   state_map[STATE_TXT_ROW].ha[3] = &pkt_end;
   state_map[STATE_TXT_ROW].event[3] = EVENT_END_MULTI_RESULT;
   state_map[STATE_TXT_ROW].next_state[3] = STATE_TXT_RS;
   state_map[STATE_TXT_ROW].num_events = 4;

   state_map[STATE_BIN_ROW].ha[0] = &pkt_binary_row;
   state_map[STATE_BIN_ROW].event[0] = EVENT_ROW;
   state_map[STATE_BIN_ROW].next_state[0] = STATE_BIN_ROW;
   state_map[STATE_BIN_ROW].ha[1] = &pkt_ok;
   state_map[STATE_BIN_ROW].event[1] = EVENT_OK;
   state_map[STATE_BIN_ROW].next_state[1] = STATE_BIN_ROW;
   state_map[STATE_BIN_ROW].ha[2] = &pkt_end;
   state_map[STATE_BIN_ROW].event[2] = EVENT_END;
   state_map[STATE_BIN_ROW].next_state[2] = STATE_SLEEP;
   state_map[STATE_BIN_ROW].num_events = 3;

   state_map[STATE_NOT_CONNECTED].ha[0] = &pkt_handshake_server;
   state_map[STATE_NOT_CONNECTED].event[0] = EVENT_SERVER_HANDSHAKE;
   state_map[STATE_NOT_CONNECTED].next_state[0] = STATE_CLIENT_HANDSHAKE;
   state_map[STATE_NOT_CONNECTED].num_events = 1;

   state_map[STATE_CLIENT_HANDSHAKE].ha[0] = &pkt_handshake_client;
   state_map[STATE_CLIENT_HANDSHAKE].event[0] = EVENT_CLIENT_HANDSHAKE;
   state_map[STATE_CLIENT_HANDSHAKE].next_state[0] = STATE_OK;
   state_map[STATE_CLIENT_HANDSHAKE].num_events = 1;

   state_map[STATE_COM_PONG].ha[0] = &pkt_ok;
   state_map[STATE_COM_PONG].event[0] = COM_PONG;
   state_map[STATE_COM_PONG].next_state[0] = STATE_SLEEP;
   state_map[STATE_COM_PONG].num_events = 1;
}
