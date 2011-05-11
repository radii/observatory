-- roots is created with hackparse --roots --table roots

drop table if exists old_roots;
drop table if exists new_roots;

create table old_roots (fingerprint varchar(100));
create table new_roots (fingerprint varchar(100));

insert into old_roots select distinct roots.fingerprint from roots join valid_certs on roots.fingerprint=valid_certs.fingerprint;

insert into new_roots (select distinct fingerprint from roots where roots.fingerprint not in (select fingerprint as f from old_roots));

insert into ca_skids 
  select Subject as ca_subj, -1 as certid, 
         `X509v3 extensions:X509v3 Subject Key Identifier` as skid, 
         0 as children 
  from roots natural join new_roots;

