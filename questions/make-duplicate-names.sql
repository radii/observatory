drop table if exists duplicate_names;
create table duplicate_names (name varchar(100));

insert into duplicate_names
  select name
  from names
  group by name
  having count(*)>1;

create index dn on duplicate_names(name);

