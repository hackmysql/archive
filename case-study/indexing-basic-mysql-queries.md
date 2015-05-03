# Indexing Basic MySQL Queries


> **NOTE**: This case study was written around 2003 and has not been updated to reflect new versions and features of MySQL. Be sure to read the [MySQL manual](http://dev.mysql.com/doc/) for your version of MySQL and consult other, more modern material on MySQL performance and best practices.

"Why is the server so slow?" That's what a customer was asking in regards to her server with dual 2.8 GHz Xeon CPUs and 3G of RAM. Her primary website was a bulletin board with over 25,000 registered users and 151,000 posts. Not a huge site, but extremely high bandwidth due to 62,000 files totaling 110 Gigs which were all uploaded and accessed with the attachment mod for [php](http://www.phpbb.com/).

When I started working on this server a load of 200 was not uncommon, and MySQL was always the culprit. The basics all checked out: plenty of server capacity, normal MySQL and Apache configs, no hardware or network problems. However, one thing kept showing up: a slow query. Fortunately, another engineer had enabled slow query logging in my.cnf:

```
log-slow-queries
long_query_time = 5
```

The slow query log file reached 2G in size after a few days, and almost every query was like:

```sql
# Query_time: 5 Lock_time: 0 Rows_sent: 1 Rows_examined: 61043
SELECT attach_id as total_attachment FROM phpbb_attachments
WHERE post_id IN (163246, 164224, 164894, 165146, 167931);
```

Some of those queries had hundreds of `post_id` specified for `IN`. This a mild example of the horrors within. I say "horrors" because this query is short and sweet, right? Oh no, look: `Rows_sent: 1 Rows_examined: 61043`. Examining 61,043 rows to return just 1 is not short or sweet. Multiply this by 200 visitors and MySQL is examining _12,208,600 rows_! It's difficult to believe but it gets worse when we see where this slow query is coming from and how often it runs.

At first I thought: what can I do about some else's query? I did everything I could for the server and besides, can one query really bring down such a powerful machine? There's only one way to find out: hack it.

## Hacking Some Else's Slow Query

First we must understand why the query is slow in the mind of MySQL, and the only way to do that is to have MySQL [EXPLAIN](http://dev.mysql.com/doc/refman/5.0/en/explain.html) it to us:

```
mysql> EXPLAIN
    -> SELECT attach_id AS total_attachment FROM phpbb_attachments
    -> WHERE post_id IN (163246, 164224, 164894, 165146, 167931);
+-------------------+-------+---------------+-------------------+---------+------+-------+--------------------------+
| table             | type  | possible_keys | key               | key_len | ref  | rows  | Extra                    |
+-------------------+-------+---------------+-------------------+---------+------+-------+--------------------------+
| phpbb_attachments | index | NULL          | attach_id_post_id |       6 | NULL | 61834 | Using where; Using index |
+-------------------+-------+---------------+-------------------+---------+------+-------+--------------------------+
```

It's a thing of beauty to see inside the mind of the machine, but in this case perhaps not. Why is MySQL telling us there are no possible index (`possible_keys` is `NULL`) but it's using index `attach_id_post_id` (listed under `key`)? And if it's using an index then why does it report it will have to examine 61,834 rows by performing a full index scan (`type: index`)? It seems there's a problem with the indexes, so let's examine them:

```
mysql> DESCRIBE phpbb_attachments;
+-------------+-----------------------+------+-----+---------+-------+
| Field       | Type                  | Null | Key | Default | Extra |
+-------------+-----------------------+------+-----+---------+-------+
| attach_id   | mediumint(8) unsigned |      | MUL | 0       |       |
| post_id     | mediumint(8) unsigned |      |     | 0       |       |
| privmsgs_id | mediumint(8) unsigned |      |     | 0       |       |
| user_id_1   | mediumint(8)          |      |     | 0       |       |
| user_id_2   | mediumint(8)          |      |     | 0       |       |
+-------------+-----------------------+------+-----+---------+-------+

mysql> SHOW INDEX FROM phpbb_attachments;
+-------------------+------------+-----------------------+--------------+-------------+-----------+-------------+
| Table             | Non_unique | Key_name              | Seq_in_index | Column_name | Collation | Cardinality |
+-------------------+------------+-----------------------+--------------+-------------+-----------+-------------+
| phpbb_attachments |          1 | attach_id_post_id     |            1 | attach_id   | A         |       61834 |
| phpbb_attachments |          1 | attach_id_post_id     |            2 | post_id     | A         |       61834 |
| phpbb_attachments |          1 | attach_id_privmsgs_id |            1 | attach_id   | A         |       61834 |
| phpbb_attachments |          1 | attach_id_privmsgs_id |            2 | privmsgs_id | A         |       61834 |
+-------------------+------------+-----------------------+--------------+-------------+-----------+-------------+
```

Understanding indexes is a two-part process: first understand the table structure, _then_ understand the indexes. You can't just slap an index on a table and make everything wonderful. In this example it looks like everything should be wonderful with index `attach_id_post_id` because the query selects `attach_id` and uses `post_id` and those columns are indexed. So why isn't it working? It is working, just not how we're expecting; it's working for MySQL which is why EXPLAIN says "Using index", but this means:

>The column information is retrieved from the table using only information in the index tree without having to do an additional seek to read the actual row.

In other words: MySQL finds matching rows and returns the selected column values using only the index in memory, not the table on disk. This is normally a good thing because RAM is a lot faster than disk, but it's not good when MySQL must examine million values to return only a single value. The ratio of effort (`Rows_examined`) to result (`Rows_sent`) is so skewed that it causes poor performance.

So MySQL is using the index but still effectively examining every row of the table. The reason is due to how MySQL uses multi-column indexes. From `DESCRIBE` we see "MUL" for multi-column index, and from `SHOW INDEX` we see `attach_id_post_id` twice, first for `attach_id`, second for `post_id`. A multi-column index is like a single column index with all columns put end-to-end in the order specified by `Seq_in_index` from `SHOW INDEX`. For example, if a row has values `attach_id=100` and `post_id=200` then the index contains `100, 200` for that row. *Knowing index column order is critically important because MySQL can only use a multi-column index when a value is specified for the first (left-most) column of the index.*

The first column of the index is `attach_id`, but the query doesn't specify a value for this column. This is why MySQL reports that it can't use the index (it's not listed under `possible_keys`). However, MySQL uses the index anyway (listed under `key`) because what it's doing is using any value for `attach_id`, then using the values specified for `post_id`. In effect, MySQL looks for `*, 16324`, `*, 164224`, `*, 164894`, `*, 165146`, and `*, 167931`. Since `attach_id` is unique MySQL must look at every single value, all 61,00+. While doing that, if it comes across one matching `post_id`, then lucky for us.

Knowing that the column order of indexes determines if and how MySQL can use them, the solution is simple: swap the order of columns in the index: `post_id` then `attach_id`. We'll do this later, but first it's good learning to examine another possibility.

## The Little Index That Could

Here's an idea: if `post_id` is what we're matching rows on, just index `post_id`. The command would be `CREATE INDEX test_index ON phpbb_attachments (post_id);`. Then EXPLAIN the exact same slow query again:

```sql
mysql> EXPLAIN
    -> SELECT attach_id as total_attachment FROM phpbb_attachments
    -> WHERE post_id IN (163246, 164224, 164894, 165146, 167931);
+-------------------+-------+---------------+------------+---------+------+------+-------------+
| table             | type  | possible_keys | key        | key_len | ref  | rows | Extra       |
+-------------------+-------+---------------+------------+---------+------+------+-------------+
| phpbb_attachments | range | test_index    | test_index |       3 | NULL |    5 | Using where |
+-------------------+-------+---------------+------------+---------+------+------+-------------+
```

That output speaks volumes: 5 rows to examine. This is the index that saved the server. I have not seen the server's load go above 4 and the website is running faster with more users at once. The difference was night and day. But why stop there? The query is no longer slow but it could be better. Notice how MySQL is not "Using index" anymore. This is because `attach_id` is not in the index its using. Whereas it's in the `attach_id_post_id` index, MySQL has wisely chosen to examine fewer rows at the cost of doing a few disk seeks. The solution is a multiple column index on both `post_id` and `attach_id`, with `post_id first`.

## The Solution

```sql
mysql> CREATE INDEX post_id_attach_id ON phpbb_attachments (post_id, attach_id);
Query OK, 61834 rows affected (0.53 sec)
Records: 61834  Duplicates: 0  Warnings: 0

mysql> EXPLAIN
    -> SELECT attach_id as total_attachment FROM phpbb_attachments
    -> WHERE post_id IN (163246, 164224, 164894, 165146, 167931);
+-------------------+-------+------------------------------+-------------------+---------+------+------+--------------------------+
| table             | type  | possible_keys                | key               | key_len | ref  | rows | Extra                    |
+-------------------+-------+------------------------------+-------------------+---------+------+------+--------------------------+
| phpbb_attachments | range | test_index,post_id_attach_id | post_id_attach_id |       3 | NULL |    5 | Using where; Using index |
+-------------------+-------+------------------------------+-------------------+---------+------+------+--------------------------+
```

As we can see MySQL still considers `test_index` key but chooses `post_id_attach_id` because doing so will allow it to get matching `attach_id` from the index instead of the disk. A simple swap of column orders in the index made all the difference. As the saying goes: it takes one tree to make a thousand matches and one match to burn a thousand trees down.

## Hacking the Source

Let's be clear about cause and effect: the slow query we just fixed was only the effect, but some code is causing it to execute. Finding the source code is easy: grep for the SQL statement. In this example the source code is attachment mod's addition to phpBB's index.php and viewforum.php scripts (one slight difference in each script):

```php
$sql = "SELECT post_id FROM " . POSTS_TABLE
     . " WHERE topic_id = $topic_id GROUP BY post_id";

if ( !($result = $db->sql_query($sql)) ) {
	message_die(GENERAL_ERROR, 'Could not query post information', '', __LINE__, __FILE__, $sql);
}

$post_ids = '';
while ( $row = $db->sql_fetchrow($result) ) {
	$post_ids .= ($post_ids == '') ? $row['post_id'] : ', ' . $row['post_id'];
}

if ( $post_ids != '' ) {
	$sql = "SELECT attach_id as total_attachment FROM " . ATTACHMENTS_TABLE
		 . " WHERE post_id IN (" . $post_ids . ")";

	if ( !($result2 = $db->sql_query($sql)) ) {
		message_die(GENERAL_ERROR, 'Could not query attachment information', '', __LINE__, __FILE__, $sql);
	}

	$attach_num = $db->sql_numrows($result2);
}
else {
	$attach_num = 0;
}
```

This query runs every time a visitor views the forum index or views the topics in a forum. Before we fixed the slow query, if 200 hundred visitors navigated from the index to a topic, MySQL would have examined about 24,417,200 rows. Now it may examine a few thousand at worse.

What's more interesting is the purpose this query serves: it counts the number of attachments for a given forum or topic. Instead of using the SQL [COUNT function](http://dev.mysql.com/doc/refman/5.0/en/counting-rows.html) to return one row with the sum, it fetches and counts all matching rows. In some cases this means it matches and counts hundreds of rows when MySQL could do this internally. Ultimately the PHP function `mysql_num_rows` is called to count the rows returned, so perhaps this function is optimized to know ahead of time how many rows were returned without actually counting them. Still it seems more logical just to use the `COUNT` function.

Let's go even deeper and look at the first query in this mod:

```php
$sql = "SELECT post_id FROM " . POSTS_TABLE
	 . "WHERE topic_id = $topic_id GROUP BY post_id";
```

MySQL EXPLAIN says:

```sql
mysql> EXPLAIN SELECT post_id FROM phpbb_posts WHERE topic_id=30 GROUP BY post_id;
+-------------+------+---------------+----------+---------+-------+------+----------------------------------------------+
| table       | type | possible_keys | key      | key_len | ref   | rows | Extra                                        |
+-------------+------+---------------+----------+---------+-------+------+----------------------------------------------+
| phpbb_posts | ref  | topic_id      | topic_id |       3 | const |    3 | Using where; Using temporary; Using filesort |
+-------------+------+---------------+----------+---------+-------+------+----------------------------------------------+
```

Type "ref," using a key, returns 1 row--that's all great but what is "Using temporary; Using filesort"? "Using temporary" means MySQL creates a temporary table (hopefully in memory) to hold the results. According to the manual "This typically happens if the query contains GROUP BY and ORDER BY clauses that list columns differently." A filesort is not desirable either because it means "MySQL will need to do an extra pass to find out how to retrieve the rows in sorted order." Seems overkill when only 1 row is expected to be examined. To optimize this query we need to know a little about the structure of the table and the current indexes:

```sql
mysql> DESCRIBE phpbb_posts;
+-----------------+-----------------------+------+-----+---------+----------------+
| Field           | Type                  | Null | Key | Default | Extra          |
+-----------------+-----------------------+------+-----+---------+----------------+
| post_id         | mediumint(8) unsigned |      | PRI | NULL    | auto_increment |
| topic_id        | mediumint(8) unsigned |      | MUL | 0       |                |
| forum_id        | smallint(5) unsigned  |      | MUL | 0       |                |
... (We do not need the remaining columns)

mysql> SHOW INDEX FROM phpbb_posts;
+-------------+------------+-----------+--------------+-------------+-----------+-------------+
| Table       | Non_unique | Key_name  | Seq_in_index | Column_name | Collation | Cardinality |
+-------------+------------+-----------+--------------+-------------+-----------+-------------+
| phpbb_posts |          0 | PRIMARY   |            1 | post_id     | A         |      151962 |
| phpbb_posts |          1 | forum_id  |            1 | forum_id    | A         |          23 |
| phpbb_posts |          1 | topic_id  |            1 | topic_id    | A         |       16884 |
... (We do not need the remaining indexes)
```

Basically, there's a single column index on every column. MySQL uses the `topic_id` index for the `WHERE` condition but then it must disk seek for `post_id`. Since rows on the disk can be in any order and we're grouping by a column we have to read from  disk (`post_id`), MySQL creates a temporary table and filesorts. First, MySQL has to scan the matching rows to determine how to retrieve them in sorted order; this is the extra filesort pass. Then it retrieves the rows in sorted order putting them into a temporary table because where else can it put them? The rows aren't sorted on the disk and there's no sorted index. If we had a sorted index then none of this would be necessary because all the values (for `topic_id` and `post_id`) would already exist in memory in sorted order. All we have to do is create an appropriate index:

```sql
mysql> CREATE INDEX topic_id_post_id ON phpbb_posts (topic_id, post_id);
Query OK, 151999 rows affected (3.74 sec)
Records: 151999  Duplicates: 0  Warnings: 0

mysql> EXPLAIN SELECT post_id FROM phpbb_posts WHERE topic_id=30 GROUP BY post_id;
+-------------+------+---------------------------+------------------+---------+-------+------+--------------------------+
| table       | type | possible_keys             | key              | key_len | ref   | rows | Extra                    |
+-------------+------+---------------------------+------------------+---------+-------+------+--------------------------+
| phpbb_posts | ref  | topic_id,topic_id_post_id | topic_id_post_id |       3 | const |    2 | Using where; Using index |
+-------------+------+---------------------------+------------------+---------+-------+------+--------------------------+
```

Much better: no temporary table or file sort, and getting matching `post_id` from the index instead of the disk.

## Final Thoughts

Notice how the queries we worked with in this example were painfully simple? Yet their power to bring a rather strong server down was amazing. Likewise, the solutions were equally simple and powerful. I should mention this was a special example of attachment mod and the current version does not have this slow query. If you're wondering the version of MySQL used was 4.0 and all the examples are real from a production server.

---

This work is licensed under the Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License. To view a copy of this license, visit http://creativecommons.org/licenses/by-nc-sa/4.0/.
