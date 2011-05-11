-- how many certs used weak keys in both scans?
select count(*) from 
  (select * from ssl.valid_certs natural join {
    select certid as nid    
    from blacklist 
    natural join valid_key_hashes 
  ) as x
  where `Serial Number` not in (select `Serial Number` from ssl.revoked)) as prev_vuln
join
  (select * from rescan.valid_certs natural join (
    select certid as nid    
    from blacklist 
    natural join valid_key_hashes 
  ) as x
  where `Serial Number` not in (select `Serial Number` from rescan.revoked)) as now_vuln
on now_vuln.fingerprint = prev_vuln.fingerprint;

-- how many new certs used weak keys?
select Issuer,count(*) from rescan.valid_certs natural join (
    select certid as nid    
    from blacklist 
    natural join valid_key_hashes 
  ) as x
  where `Serial Number` not in (select `Serial Number` from rescan.revoked))
        and startdate > (select FROM_UNIXTIME(max(fetchtime)) from ssl.seen)
  group by Issuer;

