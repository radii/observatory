select Issuer,`X509v3 extensions:X509v3 Authority Key Identifier:keyid` as akid
from valid_certs join (
  select `X509v3 extensions:X509v3 Authority Key Identifier:keyid` as akid
  from valid_certs 
  group by akid 
  having count(distinct issuer) >1 and akid is not null
  ) ;
