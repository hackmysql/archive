// misc.c Aug 18, 2006 UNSTABLE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "user_defines.h"
#include "mysql_defines.h"
#include "misc.h"

void dump_pkt(u_char *pkt, u_int len, char only_hex)
{
   int i;

   printf("::DUMP:: ");
   for(i = 0; i < len; i++) {
      if(isprint(pkt[i]) && !only_hex) printf("%c ", pkt[i]);
      else printf("%02x ", pkt[i]);
   }
   printf("::DUMP::");
}

// Return argument of simple one-argument only commands
const u_char *get_arg(u_char *pkt, u_int len)
{
   static u_char arg[MAX_COM_ARG_LEN];

   if(len > MAX_COM_ARG_LEN) len = MAX_COM_ARG_LEN;

   pkt++;
   memcpy(arg, pkt, len - 1);
   arg[len - 1] = 0;

   return (const u_char *)arg;
}

u_char *my_strcpy(u_char *to, u_char *from, u_int to_size)
{
   u_int str_len, real_str_len;

   str_len = real_str_len = (u_int)*from;

   if(!str_len) {
      if(to) to[0] = 0;
      return (from + 1);
   }

   from++;

   if(!to)
      return (from + str_len);

   if(str_len > (to_size - 1)) str_len = to_size - 1;
   memcpy(to, from, str_len);
   to[str_len] = 0;

   return (from + real_str_len);
}

u_int G3(u_char *pkt)
{
   u_char buff[4];

   memcpy(buff, pkt, 3);
   buff[3] = 0;

   return *((u_int *)buff);
}

u_int convert_binary_number(u_char *number, u_short flags, u_int bytes, u_char *to)
{
   char      sz[16];
   u_int     len;
   long long ln = 0;
   int       n = 0;

   if(bytes == 1)       n = *number;
   else if(bytes == 2)  n = G2(number)
   else if(bytes == 4)  n = G4(number)
   else if(bytes == 8)  { memcpy((void *)&ln, number, 8); }

   // TODO: Using longlong for long makes long unsigned?
   if(bytes != 8) {
      if(flags & UNSIGNED_FLAG)
         sprintf(sz, "%u", n);
      else
         sprintf(sz, "%d", n);
   }
   else {
      if(flags & UNSIGNED_FLAG)
         sprintf(sz, "%llu", ln);
      else
         sprintf(sz, "%lld", ln);      
   }

   len = strlen(sz);

   to[0] = len;
   memcpy(to + 1, sz, len);

   return len + 1;
}

u_int convert_binary_datetime(u_char *d, u_char *to)
{
   u_char  dt_len = *d;
   u_short year  = 0;
   u_char  month = 0;
   u_char  day   = 0;
   u_char  hour  = 0;
   u_char  min   = 0;
   u_char  sec   = 0;
   char    sz[11];
   u_short len;

   if(dt_len) {
      d++;
      year  = G2(d)
      d    += 2;
      month = *d++;
      day   = *d++;
   }

   sprintf(sz, "%04u-%02u-%02u", year, month, day);
   to[0] = len = strlen(sz);
   memcpy(to + 1, sz, len);

   if(dt_len == 7) { // Datetime
      hour = *d++;
      min  = *d++;
      sec  = *d++;

      sprintf(sz,  " %02u:%02u:%02u", hour, min, sec);
      to[0] = to[0] + strlen(sz);
      memcpy(to + 1 + len, sz, strlen(sz));
      len += strlen(sz);
   }

   return len + 1;
}

u_int convert_binary_time(u_char *t, u_char *to)
{
   u_char  sign  = 0;
   u_short days  = 0;
   u_short hours = 0;
   u_short mins  = 0;
   u_short secs  = 0;
   char    sz[11];
   u_short len;

   if(*t) {
      t++;
      sign  = *t++;
      days  = G4(t)
      t    += 4;
      hours = *t++;
      mins  = *t++;
      secs  = *t++;
   }

   if(days)
      hours += (days * 24);

   sprintf(sz, "%s%02u:%02u:%02u", (sign ? "-" : ""), hours, mins, secs);
   to[0] = len = strlen(sz);
   memcpy(to + 1, sz, len);

   return len + 1;
}

u_short decode_len(u_char *pkt)
{
   /*
     0-251  0-FB  Same
     252    FC    Len in next 2
     253    FD    Len in next 4
     254    FE    Len in next 8
   */

   if(*pkt <= 0xFB) { decoded_len = *pkt;        return 1; }
   if(*pkt == 0xFC) { decoded_len = G2(pkt + 1)  return 2; }
   if(*pkt == 0xFD) { decoded_len = G4(pkt + 1)  return 4; }
//   if(*pkt == 0xFE) { decoded_len = *((ulonglong *)&pkt + 1);  return 8; }
   if(*pkt == 0xFE) { memcpy((void *)&decoded_len, pkt + 1, 8); return 8; }

   return 0;
}

const char *get_field_type(u_char type)
{
   if(type < 246)
      return field_type_names[type];

   switch(type) {
      case MYSQL_TYPE_NEWDECIMAL:  return "new decimal";
      case MYSQL_TYPE_ENUM:        return "enum";
      case MYSQL_TYPE_SET:         return "set";
      case MYSQL_TYPE_TINY_BLOB:   return "tiny BLOB";
      case MYSQL_TYPE_MEDIUM_BLOB: return "medium BLOB";
      case MYSQL_TYPE_LONG_BLOB:   return "long BLOB";
      case MYSQL_TYPE_BLOB:        return "BLOB";
      case MYSQL_TYPE_VAR_STRING:  return "var string";
      case MYSQL_TYPE_STRING:      return "string";
      case MYSQL_TYPE_GEOMETRY:    return "geometry";
   }

   return "unknown";
}

void unmask_caps(u_int caps)
{
   printf("(Caps: ");
   if(caps & CLIENT_LONG_PASSWORD)     printf("Long password, ");
   if(caps & CLIENT_FOUND_ROWS)        printf("Found rows, ");
   if(caps & CLIENT_LONG_FLAG)         printf("Get all column flags, ");
   if(caps & CLIENT_CONNECT_WITH_DB)   printf("Connect w/DB, ");
   if(caps & CLIENT_NO_SCHEMA)         printf("No schema, ");
   if(caps & CLIENT_COMPRESS)          printf("Compression, ");
   if(caps & CLIENT_ODBC)              printf("ODBC client, ");
   if(caps & CLIENT_LOCAL_FILES)       printf("LOAD DATA LOCAL, ");
   if(caps & CLIENT_IGNORE_SPACE)      printf("Ignore space, ");
   if(caps & CLIENT_PROTOCOL_41)       printf("4.1 protocol, ");
   if(caps & CLIENT_INTERACTIVE)       printf("Interactive, ");
   if(caps & CLIENT_SSL)               printf("SSL, ");
   if(caps & CLIENT_IGNORE_SIGPIPE)    printf("Ignore SIGPIPE, ");
   if(caps & CLIENT_TRANSACTIONS)      printf("Transactions, ");
   if(caps & CLIENT_RESERVED)          printf("Reserved, ");
   if(caps & CLIENT_SECURE_CONNECTION) printf("4.1 authentication, ");
   if(caps & CLIENT_MULTI_STATEMENTS)  printf("Multi-statements, ");
   if(caps & CLIENT_MULTI_RESULTS)     printf("Multi-results");
   printf(")");
}

void unmask_status(u_short status)
{
   printf("(Status: ");
   if(status & SERVER_STATUS_IN_TRANS)             printf("Transaction started, ");
   if(status & SERVER_STATUS_AUTOCOMMIT)           printf("Auto-commit, ");
   if(status & SERVER_STATUS_MORE_RESULTS)         printf("More results, ");
   if(status & SERVER_MORE_RESULTS_EXISTS)         printf("Next query, ");
   if(status & SERVER_QUERY_NO_GOOD_INDEX_USED)    printf("No good index used, ");
   if(status & SERVER_QUERY_NO_INDEX_USED)         printf("No index used, ");
   if(status & SERVER_STATUS_CURSOR_EXISTS)        printf("Cursor ready, ");
   if(status & SERVER_STATUS_LAST_ROW_SENT)        printf("Last row sent, ");
   if(status & SERVER_STATUS_DB_DROPPED)           printf("DB dropped, ");
   if(status & SERVER_STATUS_NO_BACKSLASH_ESCAPES) printf("No backslash escapes");
   printf(")");
}
