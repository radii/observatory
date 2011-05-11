-- Count for each CA cert, how many valid certs it signed:
-- (results are in the ca_skids table)

drop table if exists ca_skids;
create table ca_skids (
  ca_subj text, 
  certid integer,
  skid varchar(128), 
  children integer default 0
);

insert into ca_skids
  select Subject as ca_subj,
         certid,
         `X509v3 extensions:X509v3 Subject Key Identifier` as skid,
         0
  from valid_certs
  where valid 
  and locate("TRUE",`X509v3 extensions:X509v3 Basic Constraints:CA`);

-- pasted from roots_not_in_valid_certs.sql, but this is the right place to do this:

drop table if exists old_roots;
drop table if exists new_roots;

-- these we saw in the scan
create table old_roots (fingerprint varchar(100));

-- these only come from importing a large dataset
create table new_roots (fingerprint varchar(100));

insert into old_roots 
  select distinct roots.fingerprint 
  from roots join valid_certs 
  on roots.fingerprint=valid_certs.fingerprint;

insert into new_roots (
   select distinct fingerprint 
   from roots 
   where roots.fingerprint not in (
      select fingerprint as f from old_roots
   )
  );

-- okay now we have a decent list of the CAs, count how many things each of
-- them signed...

insert into ca_skids
  select Subject as ca_subj, -1 as certid,
         `X509v3 extensions:X509v3 Subject Key Identifier` as skid,
         0 as children
  from roots natural join new_roots;

create index skid on ca_skids(skid);

update ca_skids join (
    select ca_subj, count(*) as c
    from valid_certs join ca_skids
    on Issuer=ca_subj
    where (
      ( skid is null and 
        `X509v3 extensions:X509v3 Authority Key Identifier:keyid` is null )
      or
      `X509v3 extensions:X509v3 Authority Key Identifier:keyid` = skid
    )
    group by ca_subj
    order by c
  ) as ca_counts
  set ca_skids.children = ca_counts.c
  where ca_skids.ca_subj = ca_counts.ca_subj;

-- Now, which of the multiple name certs have one instance that was signed by
-- a rarely used CA cert?

drop table if exists interesting;
create table interesting ( 
  name varchar(50),
  children integer,
  ca_subj text,
  certid integer
);

insert into interesting 
  select name, children, ca_subj, certid
  from ca_skids join
    (select `X509v3 extensions:X509v3 Authority Key Identifier:keyid` as akid,
            Subject, `X509v3 extensions:X509v3 Subject Alternative Name` as san,
            names.name, Issuer
     from valid_certs nautral join 
          (names join duplicate_names on names.name=duplicate_names.name)) as dupes
  on ca_subj=dupes.Issuer and (
     (ca_skids.skid is null and dupes.akid is null)
      or ca_skids.skid = dupes.akid
  )
  where locate(".",name);

select * 
from interesting natural join 
  (select name from interesting group by name having min(children) < 50) as n2;

-- study this for a particular domain of interest...

select children,name,Issuer
from ca_skids join (
  select name,
         Issuer,
         `X509v3 extensions:X509v3 Authority Key Identifier:keyid` as akid 
  from names natural join valid_certs 
  where locate("paypal",name)) as icerts
on ca_subj=Issuer and((ca_skids.skid is null and icerts.akid is null) or
ca_skids.skid=icerts.akid)
order by children desc;
