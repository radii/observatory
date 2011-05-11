-- Are there any certs with different fingerprints but the same signature?
select count(*) as c 
from valid_certs
group by Signature 
having c>1;

-- What kinds of key usage fields to certs have?  Do Basic Constraints:CA and
-- key usage fields agree?
select 
  `ext:X509v3 Key Usage`,
  `ext:X509v3 Basic Constraints:CA`, 
  count(*) as c 
from valid_certs 
group by 
  `ext:X509v3 Key Usage`,
  `ext:X509v3 Basic Constraints:CA`;

-- or do this another way:

select
  `ext:X509v3 Key Usage`,
  `ext:X509v3 Basic Constraints:CA`, 
  certid
from valid_certs
where 
  (locate("Certificate Sign", `ext:X509v3 Key Usage`)!=0)
    !=
  (locate("TRUE", `ext:X509v3 Basic Constraints:CA`)!=0);

-- How many valid CA certs did we see? 621 for Firefox, 

select count(*) from valid_certs where locate("TRUE", `ext:X509v3 Basic Constraints:CA`)

-- How many Subjects hold CA certs that Firefox will believe for any domain?
-- What are those Subjects?
select Subject, count(*) 
from valid_certs 
where locate("TRUE", `ext:X509v3 Basic Constraints:CA`) 
group by Subject 
order by Subject;
-- (Answer: about 400 for Firefox, 1028 for IE!)

-- For each valid CA cert, how many leaves did it sign?

-- Show us all the chains that involve valid CNNIC certs
-- XXX needs updating for a better CApath
select Subject 
from certs_seen join valid_certs on certs_seen.fingerprint=valid_certs.fingerprint 
where certs_seen.path in (
  select path 
  from certs_seen 
  where fingerprint="SHA1 Fingerprint=68:56:BB:1A:6C:4F:76:DA:CA:36:21:87:CC:2C:CD:48:4E:DD:C2:5D"
);

-- what domains have certs with multiple Issuers [would signing keys be
-- better]?  (this is a reeeeallly slow query)
select name, Issuer from
  altNamesToCerts natural join valid_certs 
  where name in 
    (select name
     from altNamesToCerts
     group by name
     having count(*) > 1)
  group by Issuer
  having count(distinct Issuer) > 1;
-- The above is a performance failure.  Let's try this instead:

drop table if exists duplicate_names;
create table duplicate_names (name varchar(100));

insert into duplicate_names
  select name
  from names
  group by name
  having count(*)>1;

create index dn on duplicate_names(name);

-- show all names with multiple Issuers
select name,count(distinct Issuer) as cd
from valid_certs natural join 
   (select name, certid
    from names natural join duplicate_names
    order by name) as dnc
where locate("\.",name)        -- exclude local names
group by name
having cd > 1
order by cd;

-- (8083 results)

--Examples of followup queries:
select Issuer,count(*) from valid_certs natural join names where name="shinseibank.co.jp" group by Issuer;


select Issuer,count(*) from valid_certs natural join names where name="www.mac.com" group by Issuer;

-- This checks to see if the same public key is used in different certs that
-- have different CA statuses.

select md5(k) as mdk, Subject,`ext:X509v3 Basic Constraints:CA` 
from valid_certs 
  join (
    select `RSA Public Key:Modulus` as k, count(distinct 
      replace(`ext:X509v3 Basic Constraints:CA`, "(critical) ", "")) 
      as distinct_ca_values 
    from valid_certs 
    group by `RSA Public Key:Modulus` 
    having distinct_ca_values > 1) as ik 
  on `RSA Public Key:Modulus`=k 
order by mdk;

-- how many certs have multiple CN=s?  These are ambiguous in the X509 spec
-- (sassaman etc)
select count(distinct Subject) from valid_certs where Subject regexp "CN=.*CN=";

-- how many certs remain vulnerable to md5 nonsense?
select `Signature Algorithm`, count(*) 
from valid_certs 
where locate("TRUE", `ext:X509v3 Basic Constraints:CA`) 
group by `Signature Algorithm`;

--

select md5(k), issuer
from valid_certs join 
  (select `RSA Public Key:Modulus` as k, count(*) 
   from valid_certs 
   where locate("TRUE", `ext:X509v3 Basic Constraints:CA`) 
   group by `RSA Public Key:Modulus` 
   having count(distinct issuer) > 1
  ) as keys
on k=`RSA Public Key:Modulus`;

-- Very general questions....
-- How many IPs / certs do we have?
select count(distinct ip) from certs_seen;
