// packet_handlers.c Aug 18, 2006 UNSTABLE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mysql_defines.h"
#include "user_defines.h"
#include "state_map.h"
#include "packet_handlers.h"
#include "misc.h"
#include "mysqlsniffer.h"

extern struct st_options op;      // Declared in mysqlsniffer.h
extern tag_id *tag;               // Declared in mysqlsniffer.h

// MySQL server > client connection handshake pkt
int pkt_handshake_server(u_char *pkt, u_int len)
{
   if(*pkt != 0x0A || len < 29) return PKT_WRONG_TYPE;

   u_char  proto;
   u_int   caps;
   u_short status;
   u_int   thd_id;
   u_char  *ver;
   u_char  *salt1;
   u_char  *salt2;

   proto   = *pkt;
   pkt    += 1;
   ver     = pkt;
   pkt    += strlen((char *)ver) + 1;
   thd_id  = G4(pkt)
   pkt    += 4;
   salt1   = pkt;
   pkt    += strlen((char *)salt1) + 1;
   caps    = *pkt;
   pkt    += 2;
   pkt    += 1; // For character set
   status  = G2(pkt)
   pkt    += 15; // 2 for status, 13 for zero-byte padding
   salt2   = pkt;

   printf("Handshake <proto %u ver %s thd %d> ", (u_int)proto, ver, thd_id);
   if(op.verbose) unmask_caps(caps);

   return PKT_HANDLED;
}

// MySQL client > server connection handshake pkt
int pkt_handshake_client(u_char *pkt, u_int len)
{
   u_char cs;
   u_int  caps;
   u_int  max_pkt;
   u_int  pass_len;
   u_char *user;
   u_char *db;
   u_char pass[128];
   u_char b3[3];

   if(op.v40) {
      caps  = G2(pkt);
      pkt  += 2;
      memcpy(b3, pkt, 3);
      max_pkt = *((u_int *)b3);
      pkt  += 3;
      user  = pkt;
      pkt  += strlen((char *)user) + 1;
      db    = 0;
   }
   else {
      caps     = G4(pkt);
      pkt     += 4;
      max_pkt  = G4(pkt);
      pkt     += 4;
      cs       = *pkt;
      pkt     += 24;
      user     = pkt;
      pkt     += strlen((char *)user) + 1;

      pass_len = (caps & CLIENT_SECURE_CONNECTION ? *pkt++ : strlen((char *)pkt));
      memcpy(pass, pkt, pass_len);
      pass[pass_len] = 0;

      pkt += pass_len;
      db = (caps & CLIENT_CONNECT_WITH_DB ? pkt : 0);
   }

   printf("Handshake (%s auth) <user %s db %s max pkt %u> ",
            (caps & CLIENT_SECURE_CONNECTION ? "new" : "old"), user, db, max_pkt);
   if(op.verbose) unmask_caps(caps);

   return PKT_HANDLED;
}


// MySQL OK pkt
int pkt_ok(u_char *pkt, u_int len)
{
   if(*pkt == 0xFE)         return PKT_WRONG_TYPE;
   if(op.v40 && (len < 5))  return PKT_WRONG_TYPE;
   if(!op.v40 && (len < 7)) return PKT_WRONG_TYPE;

   u_int  field_count;
   u_int  rows;
   u_int  insert_id;
   u_int  status;
   u_int  warn;
   u_char msg[len];

   field_count = (u_int)*pkt++;
   rows        = (u_int)*pkt++; // TODO: Can be LC
   insert_id   = (u_int)*pkt++; //       Can be LC
   status      = G2(pkt);
   if(op.v40) { warn = 0; }
   else {
      pkt     += 2;
      warn     = G2(pkt);
   }

   printf("OK <fields %u affected rows %u insert id %u warnings %u> ",
          field_count, rows, insert_id, warn);
   if(op.verbose) unmask_status(status);

   if(len > 7 || (op.v40 && len > 5)) { // Extra info on end of pkt
      pkt += 3;
      memcpy(msg, pkt, len - 8);
      msg[len - 8] = 0;
      printf(" (%s)", msg);
   }

   return PKT_HANDLED;
}

// MySQL end pkt
int pkt_end(u_char *pkt, u_int len)
{
   if(*pkt != 0xFE || len > 5) return PKT_WRONG_TYPE;

   u_short warn = 0;
   u_short status = 0;

   if(len > 1) { // 4.1+
      pkt++;
      warn    = G2(pkt);
      pkt    += 2;
      status  = G2(pkt);

      if((tag->state == STATE_TXT_ROW || tag->state == STATE_BIN_ROW) &&
         status & SERVER_MORE_RESULTS_EXISTS &&
         tag->event != EVENT_END_MULTI_RESULT)
            return PKT_WRONG_TYPE;
   }

   printf("End ");

   if(status & SERVER_MORE_RESULTS_EXISTS) printf("Multi-Result ");

   if(len > 1) { // 4.1+
      printf("<warnings %u> ", warn);
      if(op.verbose) unmask_status(status);
   }

   return PKT_HANDLED;
}

// MySQL error message pkt
int pkt_error(u_char *pkt, u_int len)
{
   if(*pkt != 0xFF) return PKT_WRONG_TYPE;

   u_short err_code;
   u_char sql_state[7], err_pkt[255];

   pkt++;
   err_code = G2(pkt);
   pkt += 2;
   if(op.v40) {
      sql_state[0] = 0;
      memcpy(err_pkt, pkt, (len - 3));
      err_pkt[len - 3] = 0;
   }
   else {
      memcpy(sql_state, pkt, 6);
      sql_state[6] = 0;
      pkt += 6;
      memcpy(err_pkt, pkt, (len - 9));
      err_pkt[len - 9] = 0;
   }

   printf("Error %u (%s): %s", err_code, sql_state, err_pkt);

   return PKT_HANDLED;
}

int pkt_com_x(u_char *pkt, u_int len)
{
   if(len > 1 || *pkt > COM_END) return PKT_WRONG_TYPE;

   int pkt_match_event = 0;

   // Does pkt match event?
   switch(tag->event) {
      case COM_QUIT:       pkt_match_event = MATCH(*pkt, COM_QUIT);       break;
      case COM_PING:       pkt_match_event = MATCH(*pkt, COM_PING);       break;
      case COM_STATISTICS: pkt_match_event = MATCH(*pkt, COM_STATISTICS); break;
      case COM_DEBUG:      pkt_match_event = MATCH(*pkt, COM_DEBUG);      break;
      default: pkt_match_event = 0;
   }

   if(!pkt_match_event) return PKT_WRONG_TYPE;

   printf("COM_%s", command_name[*pkt]);

   if(tag->event == COM_QUIT) remove_tag(tag);

   return PKT_HANDLED;
}

int pkt_com_x_string(u_char *pkt, u_int len)
{
   if(len == 1 || *pkt > COM_END) return PKT_WRONG_TYPE;

   int pkt_match_event = 0;

   // Does pkt match event?
   switch(tag->event) {
      case COM_QUERY:        pkt_match_event = MATCH(*pkt, COM_QUERY);        break;
      case COM_FIELD_LIST:   pkt_match_event = MATCH(*pkt, COM_FIELD_LIST);   break;
      case COM_INIT_DB:      pkt_match_event = MATCH(*pkt, COM_INIT_DB);      break;
      case COM_CREATE_DB:    pkt_match_event = MATCH(*pkt, COM_CREATE_DB);    break;
      case COM_DROP_DB:      pkt_match_event = MATCH(*pkt, COM_DROP_DB);      break;
      case COM_STMT_PREPARE: pkt_match_event = MATCH(*pkt, COM_STMT_PREPARE); break;

      default: pkt_match_event = 0;
   }

   if(!pkt_match_event) return PKT_WRONG_TYPE;

   printf("COM_%s: %s", command_name[*pkt], get_arg(pkt, len));

   return PKT_HANDLED;
}

int pkt_com_x_int(u_char *pkt, u_int len)
{
   if(len == 1 || len > 5) return PKT_WRONG_TYPE;

   int pkt_match_event = 0;

   // Does pkt match event?
   switch(tag->event) {
      case COM_PROCESS_KILL: pkt_match_event = MATCH(*pkt, COM_PROCESS_KILL); break;
      case COM_REFRESH:      pkt_match_event = MATCH(*pkt, COM_REFRESH);      break;
      case COM_STMT_CLOSE:   pkt_match_event = MATCH(*pkt, COM_STMT_CLOSE);   break;
      default: pkt_match_event = 0;
   }

   if(!pkt_match_event) return PKT_WRONG_TYPE;

   printf("COM_%s: ", command_name[*pkt]);
   *pkt++;
   printf("%u", get_uint(pkt));

   return PKT_HANDLED;
}

int pkt_string(u_char *pkt, u_int len)
{
   if(len == 1) return PKT_WRONG_TYPE;

   u_char buff[len + 1];

   memcpy(buff, pkt, len);
   buff[len] = 0;

   printf("%s", buff);

   return PKT_HANDLED;
}

int pkt_n_fields(u_char *pkt, u_int len)
{
   if(len > 1) return PKT_WRONG_TYPE;

   decode_len(pkt);

   printf("%llu Fields", decoded_len);

   if(EVENT_NUM_FIELDS_BIN) {
      tag->n_fields      = (u_int)*pkt; // Used by pkt_binary_row()
      tag->current_field = 0; // Used by pkt_field()

      if(!tag->fields) // tag->fields populated in pkt_field()
         tag->fields = (field_types *)malloc(sizeof(field_types));
   }

   return PKT_HANDLED;
}

// MySQL field description pkt
int pkt_field(u_char *pkt, u_int len)
{
   if(*pkt == 0xFE) return PKT_WRONG_TYPE;

   u_int   field_len;
   u_char  db[256];
   u_char  table[256];
   u_char  field[256];
   u_short field_type;
   u_short flags;

   // TODO: need to handle decimals and default

   if(op.v40) {
      db[0] = 0;
      pkt   = my_strcpy(table, pkt, 256);
      pkt   = my_strcpy(field, pkt, 256);
      pkt  += 1;
      field_len = G3(pkt);
      pkt  += 3;
      pkt  += 1; // For LCB on type
      field_type = *pkt++;
      pkt  += 1; // For LCB on flags
      flags = *pkt; // TODO: This has an 03 LCB but is supposedly only 2 bytes?
   }
   else {
      pkt  += 4; // Db length
      pkt   = my_strcpy(db, pkt, 256);
      pkt   = my_strcpy(table, pkt, 256);
      pkt   = my_strcpy(0, pkt, 256); // Org. table
      pkt   = my_strcpy(field, pkt, 256);
      pkt   = my_strcpy(0, pkt, 256); // Org. name
      pkt  += 3;
      field_len = G4(pkt);
      pkt  += 4;
      field_type = *((u_int *)pkt);
      pkt  += 1;
      flags = G2(pkt)
   }

   if(tag->event == EVENT_FIELD_BIN) {
      tag->fields->field_type[tag->current_field] = field_type;
      tag->fields->field_flags[tag->current_field++] = flags;
   }

   printf("Field: %s.%s.%s <type %s (%u) size %u>", db, table, field,
          get_field_type(field_type), (u_int)field_type, field_len);

   return PKT_HANDLED;
}

/*
  MySQL data row pkt (1 pkt per row):
   Row 1 Col 1 length   1 byte
   Row 1 Col 1 data     string
   ...
   Row 1 Col N length   1 byte
   Row 1 Col N data     string
*/
int pkt_row(u_char *pkt, u_int len)
{
   if(*pkt == 0xFE && (len == 1 || len == 5)) return PKT_WRONG_TYPE; // Is End pkt

   u_int   n;
   u_int   end = 0;
   u_char  col_LC;
   u_char  col_truncated = 0;
   ulonglong col_len;
   ulonglong real_col_len;
   static u_char col_data[MAX_COL_LEN + 9]; // +9 for '::TRUNC::' if necessary

   printf("||");
   while(1) {
      col_LC = *pkt;

      n = decode_len(pkt);
      real_col_len = col_len = decoded_len;

      // 1 for LC, n if LC followed in 2, 4, or 8 bytes
      pkt = pkt + 1 + (n > 1 ? n : 0);
      end = end + 1 + (n > 1 ? n : 0);

      if(col_LC != 0xFB) { // Column is not NULL
         if(col_len > MAX_COL_LEN - 1) {
            col_len = MAX_COL_LEN - 1;
            col_truncated = 1;
         }

         if(col_len) {
            memcpy(col_data, pkt, col_len);
            if(col_truncated) {
               memcpy(col_data + col_len, "::TRUNC::", 9);
               col_data[col_len + 9] = 0;
            }
            else
               col_data[col_len] = 0;

            printf(" %s |", col_data);
         }
         else
            printf("  |"); // Empty string ''
      }
      else {
         real_col_len = 0;
         printf(" NULL |");
      }

      if((end + real_col_len) >= len) break;

      col_truncated = 0;

      pkt += real_col_len;
      end += real_col_len;
   }
   printf("|");

   return PKT_HANDLED;
}

/*
  MySQL binary data row pkt (1 pkt per row):
   Zero byte            1 byte
   NULL bitmap          1..n bytes
   ...
   Row 1 Col A length   1 byte
   Row 1 Col A data     string
   ...
   Row 1 Col Z length   1 byte
   Row 1 Col Z data     string

   This function converts/expands pkt from binary to regular (text)
   protocol then passes it to pkt_row() for output processing.
*/
int pkt_binary_row(u_char *pkt, u_int len)
{
   if(*pkt != 0x00) return PKT_WRONG_TYPE;

   u_int   byte, bit, col;
   u_int   col_len;
   u_int   col_len_expanded;
   u_short n_bitmap_bytes = (tag->n_fields + 7 + 2) / 8;
   u_int   null_bitmap[16]; // 512 columns max
   u_short bb;
   u_char  txt_row[len + tag->n_fields];
   u_char  *row;
   u_int   row_len;
   u_short flags;

   pkt++;

   memset(null_bitmap, 0, sizeof(null_bitmap));

   null_bitmap[0] = *pkt++ >> 2;

   for(byte = 1, col = 6; byte < n_bitmap_bytes; byte++, pkt++) {
      for(bit = 0; bit < 8; bit++, col++) {
         bb = col / 32;
         null_bitmap[bb] |= (((*pkt >> bit) & 1) << (col - (32 * bb)));
      }
   }

   row     = txt_row;
   row_len = 0;

   for(col = 0; col <= tag->n_fields - 1; col++) {
      bb = col / 32;
      if(null_bitmap[bb] & (1 << (col - (bb * 32)))) { // Column is NULL
         *row++ = 0xFB;
         row_len++;
      }
      else {
         flags = tag->fields->field_flags[col];

         col_len_expanded = col_len = 0;

         switch(tag->fields->field_type[col])
         {  // Numerics
            case 1: col_len_expanded = convert_binary_number(pkt, flags, 1, row); col_len = 1; break;
            case 2: col_len_expanded = convert_binary_number(pkt, flags, 2, row); col_len = 2; break;
            case 3: col_len_expanded = convert_binary_number(pkt, flags, 4, row); col_len = 4; break;
            case 8: col_len_expanded = convert_binary_number(pkt, flags, 8, row); col_len = 8; break;
            // Date, datetime
            case 10:
            case 12:
                     col_len = ((u_short)*pkt) + 1;
                     col_len_expanded = convert_binary_datetime(pkt, row);
                     break;
            // Time
            case 11:
                     col_len = ((u_short)*pkt) + 1;
                     col_len_expanded = convert_binary_time(pkt, row);
                     break;
            // Strings and BLOBS
            case  15:
            case 249:
            case 250:
            case 251:
            case 252:
            case 253:
            case 254:
                      col_len = col_len_expanded = ((u_short)*pkt) + 1; // This can be LC
                      bit = decode_len(pkt);
                      col_len += (bit > 1 ? bit : 0); // If it was LC, bit will be > 1
                      col_len_expanded = col_len;
                      memcpy(row, pkt, col_len);
                      break;
            default:
               break;
         }

         row     += col_len_expanded;
         row_len += col_len_expanded;
         pkt     += col_len;
      }
   }

   row = txt_row;

   return pkt_row(row, row_len);
}

/*
   MySQL prepared statement metadata pkt:
     0 byte         1 byte
     Stmt ID        4 bytes
     Num. columns   2 bytes
     Num. params    2 bytes
     0 byte         1 byte
     Warnings       2 bytes
*/
int pkt_stmt_meta(u_char *pkt, u_int len)
{
   if(len != 12) return PKT_WRONG_TYPE;

   u_int   stmt_id;
   u_short n_cols;
   u_short n_params;
   u_short warns;

   *pkt++;
   stmt_id = G4(pkt);
   pkt += 4;
   n_cols = G2(pkt);
   pkt += 2;
   n_params = G2(pkt);
   pkt += 3;
   warns = G2(pkt);

   printf("Statement ID %u <%u params %u columns %u warnings>", stmt_id, n_params, n_cols, warns);

   return PKT_HANDLED;
}

int pkt_stmt_execute(u_char *pkt, u_int len)
{
   if(!MATCH(*pkt, COM_STMT_EXECUTE)) return PKT_WRONG_TYPE;

   u_int   stmt_id;
   u_int   itr;
   /*
     Can't figure these unless we track the number of params for each stmt ID
   u_short null_bitmap;
   u_short new_prep;
   */

   pkt++;
   stmt_id = G4(pkt);
   pkt += 5;
   itr = G4(pkt);

   printf("COM_EXECUTE Statement ID %u <iteration %u>", stmt_id, itr);

   return PKT_HANDLED;
}
