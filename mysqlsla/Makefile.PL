use 5.008004;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME              => 'mysqlsla',
    VERSION_FROM      => 'lib/mysqlsla.pm',
    PREREQ_PM         => {},
    ($] >= 5.005 ?
      (ABSTRACT_FROM  => 'lib/mysqlsla.pm', # retrieve abstract from module
       AUTHOR         => 'Daniel Nichter (http://hackmysql.com/contact)') : ()),
    EXE_FILES         => [ 'bin/mysqlsla' ],
);
