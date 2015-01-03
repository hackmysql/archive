// mysqlsniffer.h Aug 18, 2006 UNSTABLE

// Every logical MySQL packet starts w/ this 4 byte header
struct mysql_hdr {
   u_int pkt_length:24, pkt_id:8;
};

#define ORIGIN_SERVER 1
#define ORIGIN_CLIENT 2

struct st_options {
   u_short port:1,
           verbose:1,
           tcp_ctrl:1,
           net_hdrs:1,
           no_myhdrs:1,
           state:1,
           dump:1,
           v40:1;
   u_short port_n;
};
struct st_options op;      // Command line options

struct st_field_types {
   u_char field_type[MAX_FIELD_TYPES];
   u_short field_flags[MAX_FIELD_TYPES];
};
typedef struct st_field_types field_types;

struct st_tag_id {
   u_int   id_address;
   u_short id_port;
   short   current_origin:8, current_pkt_id:8;
   short   last_origin:8,    last_pkt_id:8;
   u_short state;
   u_short event;
   u_char  pkt_fragment;
   u_char  *frag;
   u_int   frag_len;
   u_int   n_fields;
   field_types *fields;
   u_short current_field;
};
typedef struct st_tag_id tag_id;

tag_id tags[MAX_TAGS];
tag_id *tag;               // Information about the current connection

void remove_tag(tag_id *tag);
