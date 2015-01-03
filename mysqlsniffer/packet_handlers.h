// packet_handlers.h Aug 18, 2006 UNSTABLE

#define PKT_WRONG_TYPE    0
#define PKT_HANDLED       1
#define PKT_PARSED_OK     1
#define PKT_UNKNOWN_STATE 2
#define PKT_DETERMINED    3
#define PKT_FRAGMENTED    4

int pkt_handshake_server(u_char *pkt, u_int len);
int pkt_handshake_client(u_char *pkt, u_int len);
int pkt_ok(u_char *pkt, u_int len);
int pkt_end(u_char *pkt, u_int len);          // Last data or end
int pkt_error(u_char *pkt, u_int len);        // Always and only 0xFF
int pkt_com_x(u_char *pkt, u_int len);        // Command ID only
int pkt_com_x_string(u_char *pkt, u_int len); // Command ID w/ string
int pkt_com_x_int(u_char *pkt, u_int len);    // Command ID w/ integer
int pkt_string(u_char *pkt, u_int len);       // String only
int pkt_n_fields(u_char *pkt, u_int len);
int pkt_field(u_char *pkt, u_int len);
int pkt_row(u_char *pkt, u_int len);
int pkt_binary_row(u_char *pkt, u_int len);
int pkt_stmt_meta(u_char *pkt, u_int len);
int pkt_stmt_execute(u_char *pkt, u_int len);
