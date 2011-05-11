select path from valid_certs where locate("CA", `Netscape Cert Type`);
select path from all_certs where locate("CA", `Netscape Cert Type`);

select  distinctrow `Serial Number`, 
       `X509v3 extensions:Netscape Cert Type`, 
       `X509v3 extensions:X509v3 Basic Constraints:CA` 
from  valid_certs 
where locate("CA",`X509v3 extensions:Netscape Cert Type`);
