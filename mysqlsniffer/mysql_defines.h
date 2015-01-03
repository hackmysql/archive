// mysql_defines.h Aug 18, 2006 UNSTABLE


// Copied from include/mysql_com.h [44-57]
enum enum_server_command
{
  COM_SLEEP, COM_QUIT, COM_INIT_DB, COM_QUERY, COM_FIELD_LIST,
  COM_CREATE_DB, COM_DROP_DB, COM_REFRESH, COM_SHUTDOWN, COM_STATISTICS,
  COM_PROCESS_INFO, COM_CONNECT, COM_PROCESS_KILL, COM_DEBUG, COM_PING,
  COM_TIME, COM_DELAYED_INSERT, COM_CHANGE_USER, COM_BINLOG_DUMP,
  COM_TABLE_DUMP, COM_CONNECT_OUT, COM_REGISTER_SLAVE,
  COM_STMT_PREPARE, COM_STMT_EXECUTE, COM_STMT_SEND_LONG_DATA, COM_STMT_CLOSE,
  COM_STMT_RESET, COM_SET_OPTION, COM_STMT_FETCH,
  /* don't forget to update const char *command_name[] in sql_parse.cc */

  /* Must be last */
  COM_END
};

// Copied from sql/sql_parse.cc [77-85] and capitalized and s/ /_/g by me
static const char *command_name[]={
   "SLEEP", "QUIT", "INIT_DB", "QUERY", "FIELD_LIST", "CREATE_DB",
   "DROP_DB", "REFRESH", "SHUTDOWN", "STATISTICS", "PROCESSLIST",
   "CONNECT","KILL","DEBUG","PING","TIME","DELAYED_INSERT","CHANGE_USER",
   "Binlog Dump","Table Dump",  "Connect Out", "Register Slave",
   "PREPARE", "EXECUTE", "LONG_DATA", "CLOSE_STMT",
   "RESET_STMT", "Set option", "FETCH",
   "Error"                                       // Last command number
};

// Copied from include/mysql_com.h [113-130]
#define CLIENT_LONG_PASSWORD    1       /* new more secure passwords */
#define CLIENT_FOUND_ROWS       2       /* Found instead of affected rows */
#define CLIENT_LONG_FLAG        4       /* Get all column flags */
#define CLIENT_CONNECT_WITH_DB  8       /* One can specify db on connect */
#define CLIENT_NO_SCHEMA        16      /* Don't allow database.table.column */
#define CLIENT_COMPRESS         32      /* Can use compression protocol */
#define CLIENT_ODBC             64      /* Odbc client */
#define CLIENT_LOCAL_FILES      128     /* Can use LOAD DATA LOCAL */
#define CLIENT_IGNORE_SPACE     256     /* Ignore spaces before '(' */
#define CLIENT_PROTOCOL_41      512     /* New 4.1 protocol */
#define CLIENT_INTERACTIVE      1024    /* This is an interactive client */
#define CLIENT_SSL              2048    /* Switch to SSL after handshake */
#define CLIENT_IGNORE_SIGPIPE   4096    /* IGNORE sigpipes */
#define CLIENT_TRANSACTIONS     8192    /* Client knows about transactions */
#define CLIENT_RESERVED         16384   /* Old flag for 4.1 protocol  */
#define CLIENT_SECURE_CONNECTION 32768  /* New 4.1 authentication */
#define CLIENT_MULTI_STATEMENTS 65536   /* Enable/disable multi-stmt support */
#define CLIENT_MULTI_RESULTS    131072  /* Enable/disable multi-results */

// Copied from include/mysql_com.h [133-151]
#define SERVER_STATUS_IN_TRANS     1    /* Transaction has started */
#define SERVER_STATUS_AUTOCOMMIT   2    /* Server in auto_commit mode */
#define SERVER_STATUS_MORE_RESULTS 4    /* More results on server */
#define SERVER_MORE_RESULTS_EXISTS 8    /* Multi query - next query exists */
#define SERVER_QUERY_NO_GOOD_INDEX_USED 16
#define SERVER_QUERY_NO_INDEX_USED      32
/*
  The server was able to fulfill the clients request and opened a
  read-only non-scrollable cursor for a query. This flag comes
  in reply to COM_STMT_EXECUTE and COM_STMT_FETCH commands.
*/
#define SERVER_STATUS_CURSOR_EXISTS 64
/*
  This flag is sent when a read-only cursor is exhausted, in reply to
  COM_STMT_FETCH command.
*/
#define SERVER_STATUS_LAST_ROW_SENT 128
#define SERVER_STATUS_DB_DROPPED        256 /* A database was dropped */
#define SERVER_STATUS_NO_BACKSLASH_ESCAPES 512

// Copied from sql/mysql_com.h [71-86] v5.0.15
#define NOT_NULL_FLAG   1               /* Field can't be NULL */
#define PRI_KEY_FLAG    2               /* Field is part of a primary key */
#define UNIQUE_KEY_FLAG 4               /* Field is part of a unique key */
#define MULTIPLE_KEY_FLAG 8             /* Field is part of a key */
#define BLOB_FLAG       16              /* Field is a blob */
#define UNSIGNED_FLAG   32              /* Field is unsigned */
#define ZEROFILL_FLAG   64              /* Field is zerofill */
#define BINARY_FLAG     128             /* Field is binary   */
/* The following are only sent to new clients */
#define ENUM_FLAG       256             /* field is an enum */
#define AUTO_INCREMENT_FLAG 512         /* field is a autoincrement field */
#define TIMESTAMP_FLAG  1024            /* Field is a timestamp */
#define SET_FLAG        2048            /* field is a set */
#define NO_DEFAULT_VALUE_FLAG 4096      /* Field doesn't have default value */
#define NUM_FLAG        32768           /* Field is num (for clients) */

// Copied part of include/mysql_com.h [212-232]
enum enum_field_types {
                         MYSQL_TYPE_NEWDECIMAL=246,
                         MYSQL_TYPE_ENUM=247,
                         MYSQL_TYPE_SET=248,
                         MYSQL_TYPE_TINY_BLOB=249,
                         MYSQL_TYPE_MEDIUM_BLOB=250,
                         MYSQL_TYPE_LONG_BLOB=251,
                         MYSQL_TYPE_BLOB=252,
                         MYSQL_TYPE_VAR_STRING=253,
                         MYSQL_TYPE_STRING=254,
                         MYSQL_TYPE_GEOMETRY=255
};


// Not from MySQL source code
static const char *field_type_names[] = {
   "decimal",
   "tiny int",
   "short int",
   "long int",
   "float",
   "double",
   "NULL",
   "timestamp",
   "longlong",
   "int24",
   "date",
   "time",
   "datetime",
   "year",
   "newdate",
   "varchar",
   "bit"
};
