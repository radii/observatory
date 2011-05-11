drop table if exists key_hashes;
drop table if exists valid_key_hashes;

create table key_hashes (
  certid integer,
  half_sha1 char(20)
);

create table valid_key_hashes (
  certid integer,
  half_sha1 char(20)
);


-- all of this madness is required because 
-- (1) "openssl rsa -modulus" produces output like this:
--       "Modulus=B460F0869B865653B0C35A2CCD7E32D7C"....
--     while our db entry looks like: "00:b4:60:f0:86"...
-- (2) debian only stores the lower 80 bits of the hashes in its blacklists
insert into key_hashes
select certid, 
       substring(
         sha1(
           concat(
             "Modulus=", 
             upper(
               substring( replace(`RSA Public Key:Modulus`, ":", "") ,3)
             ),
             "\n"
           )
         ),
       -20) 
       as half_sha1 
from all_certs;

insert into valid_key_hashes
select certid, 
       substring(
         sha1(
           concat(
             "Modulus=", 
             upper(
               substring( replace(`RSA Public Key:Modulus`, ":", "") ,3)
             ),
             "\n"
           )
         ),
       -20) 
       as half_sha1 
from valid_certs;

create index hs1 on key_hashes(half_sha1);
create index hs1 on valid_key_hashes(half_sha1);

select count(*) from blacklist natural join key_hashes;

select Subject,`X509v3 extensions:X509v3 Subject Alternative Name` 
from valid_certs natural join (
  select certid 
  from blacklist natural join valid_key_hashes
) as x 
where `X509v3 extensions:X509v3 Subject Alternative Name` is not null;

select `X509v3 extensions:X509v3 CRL Distribution Points` from valid_certs natural join (select certid from blacklist natural join valid_key_hashes) as x where `X509v3 extensions:X509v3 Subject Alternative Name` is not null;

