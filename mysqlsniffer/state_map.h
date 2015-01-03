// state_map.h Aug 18, 2006 UNSTABLE

typedef int (*PKT_HANDLER)(u_char *pkt, u_int len);

#define MAX_EVENTS_PER_STATE 15
struct st_events {
   u_char      num_events;
   u_char      event[MAX_EVENTS_PER_STATE];
   u_char      next_state[MAX_EVENTS_PER_STATE];
   PKT_HANDLER ha[MAX_EVENTS_PER_STATE];
};

#define NUM_STATES 17
struct st_events state_map[NUM_STATES];

static const char *state_name[] = {
   "One String",
   "OK",
   "Field List",
   "Sleep",
   "Field (txt)",
   "Field (bin)",
   "Result (txt)",
   "Result (bin)",
   "End",
   "Error",
   "Row (txt)",
   "Row (bin)",
   "Not Connected",
   "Client handshake",
   "COM_PONG",
   "Stmt Meta",
   "Stmt Param"
};

enum states {
   STATE_ONE_STRING,
   STATE_OK,
   STATE_FIELD_LIST,
   STATE_SLEEP,
   STATE_FIELD,
   STATE_FIELD_BIN,
   STATE_TXT_RS,
   STATE_BIN_RS,
   STATE_END,
   STATE_ERROR,
   STATE_TXT_ROW,
   STATE_BIN_ROW,
   STATE_NOT_CONNECTED,
   STATE_CLIENT_HANDSHAKE,
   STATE_COM_PONG,
   STATE_STMT_META,
   STATE_STMT_PARAM
};

enum events {
   // Events 0-29 are enum_server_command
   EVENT_END=30,
   EVENT_NUM_FIELDS=31,
   EVENT_ERROR=32,
   EVENT_ONE_STRING=33,
   EVENT_ROW=34,
   EVENT_FIELD=35,
   EVENT_OK=36,
   EVENT_CLIENT_HANDSHAKE=37,
   EVENT_SERVER_HANDSHAKE=38,
   EVENT_FL_FIELD=39,
   EVENT_END_MULTI_RESULT=40,
   EVENT_STMT_META=41,
   EVENT_STMT_PARAM=42,
   COM_PONG=43,
   EVENT_NUM_FIELDS_BIN=44,
   EVENT_FIELD_BIN=45
};
