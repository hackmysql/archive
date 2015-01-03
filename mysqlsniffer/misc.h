// misc.h Aug 18, 2006 UNSTABLE

#define G2(x) *((u_short *)x);
#define G4(x) *((u_int *)x);
#define MATCH(a, b) (a == b ? 1 : 0)

typedef unsigned long long ulonglong; // 8 bytes
ulonglong decoded_len;     // Set by decode_len()

void dump_pkt(u_char *pkt, u_int len, char only_hex);
const u_char *get_arg(u_char *pkt, u_int len);
u_char *my_strcpy(u_char *to, u_char *from, u_int to_size);
static inline u_int get_uint(u_char *pkt) { return G4(pkt); }
u_int G3(u_char *pkt);
u_int convert_binary_number(u_char *number, u_short flags, u_int bytes, u_char *to);
u_int convert_binary_datetime(u_char *d, u_char *to);
u_int convert_binary_time(u_char *d, u_char *to);
u_int convert_binary_float(u_char *val, u_char *to);
const char *get_field_type(u_char type);
u_short decode_len(u_char *pkt);
void unmask_caps(u_int caps);
void unmask_status(u_short status);
