package mysqlsla;

our $VERSION = '2.03';

1;

__END__

=head1 NAME

mysqlsla - Parse, filter, analyze and sort MySQL slow, general and binary logs

=head1 SYNOPSIS

    # Basic operation: parse a MySQL slow or general log
    mysqlsla --log-type slow LOG
    mysqlsla --log-type general LOG

    # Parse output from mysqlbinlog
    # mysqlsla cannot directly parse binary logs
    mysqlbinlog LOG | mysqlsla --log-type binary -

    # Parse a microslow patched slow log
    mysqlsla --log-type msl LOG

    # Replay a replay file
    mysqlsla --replay FILE

    # Parse a user-defined log specify its format
    mysqlsla --log-type udl --udl-format FILE

    # Let mysqlsla automatically determine the log type
    mysqlsla LOG

=head1 DESCRIPTION

mysqlsla parses, filters, analyzes and sorts MySQL slow, general, binary
and microslow patched slow logs. It also supports user-defined logs.

This POD/man page is only a very brief outline of usage and command line
options. For the full library of mysqlsla documentation visit
http://hackmysql.com/mysqlslaZ<>.

=head1 .mysqlsla CONFIG FILE

Reading C<~/.mysqlsla> is the very first thing mysqlsla does when it starts.
Command line options can be set in this file (one per line). Example:

atomic-statements

statement-filter=+UPDATE,INSERT

Notice: no leading dashes (- or --), no quotations marks ("), and the form
C<option=value> when C<option> requires a value.

These options are overriden by those given on the real command line.

=head1 COMMAND LINE OPTIONS

=over 4

=item C<--log-type (-lt) TYPE LOGS>

Parse MySQL LOGS of TYPE. Default none. TYPE must be either slow, general,
binary, msl or udl. LOGS is a space-separated list of MySQL log files.

As of mysqlsla v2.03 this option is optional. If given, mysqlsla will treat
the logs as the given type. If not given, mysqlsla will automatically detect
the log type by examining the first log file.

Binary logs are a special case. mysqlsla cannot read MySQL binary log directly. You must first "decode" the binary log using mysqlbinlog without the
--short-form option. It is only the text output from mysqlbinlog that
mysqlsla can read.

If you want to use the --short-form option with mysqlbinlog you must then use TYPE udl with mysqlsla.

LOGS can also be - to make mysqlsla read from STDIN. This can be used to pipe
the output of another program into mysqlsla. However, if you use - to read from
STDIN, you must explicitly give the log type; mysqlsla cannot
automatically detect the log type from STDIN.

=item C<--abstract-in (-Ai) N>

Abstract IN () clauses further by grouping in groups of N. Disabled by default.

=item C<--abstract-values (-Av)>

Abstract VALUES () clauses further by removing the number of condensed value sets. Disabled by default.

=item C<--atomic-statements>

Treat multi-statment groups atomically when filtering. Disabled by default.

=item C<--avg (-n) N>

Average query timing over N executions. Default 1.

=item C<--databases (-db) (-D) DATABASES>

Try EXPLAINing queries which have no known database using DATABASES.
Default none. DATABASES is a comma-separated list of database names
(without spaces). Only used when option explain is used too.

=item C<--db-inheritance>

Allow queries to inherit the last database specified in the log. Disabled by default.

=item C<--debug>

Enable a flood of debugging information from both mysqlsla and MySQL::Log::ParseFilter. Disabled by
default. Use with caution.

=item C<--dist>

Calculate distribution frequency of values. Disabled by default. Requires an appropriate standard
report format line.

=item C<--dist-min-percent (-dmin) N>

Do not display dist percents less than N. Default 5.

=item C<--dist-top (-dtop) N>

Display at most N dist percentages. Default 10.

=item C<--dont-save-meta-values>

Do not save meta-property values from log. Disabled by default (meta-property values are saved).

=item C<--explain (-ex)>

EXPLAIN each query. Disabled by default. Requires an appropriate standard report format line.

=item C<--extra (-x) TINFO>

Display extra table information. TINFO can be either tschema, tcount or both
like tschema,tcount. Default none.

tschema will cause mysqlsla to print each tables structure (the output of
SHOW CREATE TABLE).

tcount will cause mysqlsla to print the number of rows in each table using
SELECT COUNT(*) FROM table.

=item C<--flush-qc>

Flush query cache before query execution timing. Disabled by default.

=item C<--grep PATTERN>

grep statements for PATTERN and keep only those which match. Default none.

=item C<--help (-?)>

Tells you to see what you are reading right now.

=item C<--host ADDRESS>

Connect to MySQL at host ADDRESS. Default localhost if no socket is available.

=item C<--meta-filter (-mf) CONDTIONS>

Set meta-properties filter using CONDITIONS. Default none. CONDITIONS is a comma-separated list of
meta-property conditions (without spaces) in the form: [meta][op][value].

[meta] refers to a meta-property name, the list of which is long: see mysqlsla v2 Filters.

[op] is either > < or =. [value] is the value, numeric or string, against which the value for [meta]
from the log must be true according to [op].

For string-based [meta], like db or host, [op] can only be =.

=item C<--microsecond-symbol (-us) STRING>

Use STRING to denote microsecond values. Default µs.

=item C<--no-mycnf>

Do not read ~/.my.cnf when initializing. Does not apply to Windows servers.

=item C<--nthp-min-values (nthpm) N>

Do not calculate Nth percent values if there are less than N values. Default 10.

=item C<--nth-percent (-nthp) N>

Calculate Nth percent values. Disabled by default or 95 if used but no N is given. Requires an
appropriate standard report format line.

=item C<--password PASS>

Use PASS as MySQL user password. If PASS is omitted, the password will be prompted for (on STDERR).

=item C<--percent>

Display a basic percentage complete indictor while timing all queries for the time-all report.
Disabled by default.

=item C<--port PORT>

Connect to MySQL on PORT. Default none (relies on system default which will be 3306).

=item C<--post-analyses-replay FILE>

Save a post-analyses replay as FILE.

=item C<--post-parse-replay FILE>

Save a post-parse replay as FILE.

=item C<--post-sort-replay FILE>

Save a post-sort replay as FILE.

=item C<--replay FILE>

Load unique queries from replay FILE. Default none.

=item C<--report-format (-rf) FILE>

Use FILE to format the standard report. Default internal report format.

=item C<--reports (-R) REPORTS>

Print REPORTS. Default standard. REPORTS is a comma-separated list of report names (without spaces).

Available reports are: standard, time-all, print-unique, print-all, dump.

WARNING: A safety SQL statement filter of "+SELECT,USE" is automatically set when using
time-each-query or the time-all report. Overriding the safety SQL statement filter by explicitly
setting another with statement-filter can permit real changes to databases. Use with caution!

=item C<--save-all-values>

Save extra "all values" for some meta-properties. Disabled by default.

=item C<--silent>

Do not print any reports. Disabled by default. Debug messages will still be printed.

=item C<--socket SOCKET>

Connect to MySQL through SOCKET. Default none (relies on system default which is compiled into
the MySQL client library).

=item C<--sort META>

Sort queries according to META. Default t_sum for slow and msl logs, c_sum for all others.
META is any meta-property name.

=item C<--statement-filter (-sf) CONDTIONS>

Set SQL statement filter using CONDITIONS. Default none. CONDITIONS is a comma-separated list of
SQL statement types  in the form: [+-][TYPE],[TYPE],etc.

The [+-] is given only once before the first [TYPE]. A + indicates a positive filter: keep only
SQL statements of [TYPE]. A - indicates a negative filter: remove only SQL statements of [TYPE].
If neither is given, - is default.

[TYPE] is a SQL statement type: SELECT, CREATE, DROP, UPDATE, INSERT, etc.

=item C<--time-each-query (-te)>

Time each query by actually executing it on the MySQL server. Disabled by default. Requires an
appropriate standard report format line.

WARNING: A safety SQL statement filter of "+SELECT,USE" is automatically set when using
time-each-query or the time-all report. Overriding the safety SQL statement filter by explicitly
setting another with statement-filter can permit real changes to databases. Use with caution!

=item C<--top N>

After sorting display only the top N queries. Default 10.

=item C<--udl-format (-uf) FILE>

Use FILE to define the format of the user-defined log (udl) instead of the default. Default is ";\n"
record separator and no headers.

=item C<--user USER>

Connect to MySQL as USER. Default user of mysqlsla process.

=back

=head1 CUSTOM REPORT FORMATS

The standard report is the human-readable report which shows all the numbers
and values calculated from the log. If no other report is specified, it is the
default report.

mysqlsla automatically formats the standard report according to a report format
depending on the log type being parsed. Therefore, the standard report for
general logs is different from slow logs and binary logs, etc. mysqlsla has,
internally, basic report formats for every log type, but a custom report format
can be explicitly set by using the C<--report-format> option.

Read http://hackmysql.com/mysqlsla_reports for more information on creating
and customizing report formats.

=head1 BUGS

I follow the zero known bugs release policy in releasing new versions of
mysqlsla. Certainly, however, bugs still exist somewhere. So when you find one, contact me through the web site at http://hackmysql.com/contactZ<>. 

=head1 SEE ALSO

http://hackmysql.com/mysqlsla

=head1 AUTHOR

Daniel Nichter (http://hackmysql.com/)

=head1 COPYRIGHT AND LICENSE

Copyright 2007-2008 Daniel Nichter

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

The GNU General Public License is available at:
http://www.gnu.org/copyleft/gpl.html

=cut
