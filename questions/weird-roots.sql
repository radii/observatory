-- Is anyone still signing stuff with md5?

select `Signature Algorithm`, count(*) 
from valid_certs 
where locate("2010", startdate) 
group by `Signature Algorithm`;

select `Serial Number`,Subject,Issuer 
from valid_certs 
where `Signature Algorithm`=" md5WithRSAEncryption" 
  and locate("2010", startdate);

-- Answer: yes, Anthem health insurance and the French Ministry of Justice
-- both have predictable SNs, too, but hopefully do not issue certs to
-- arbitrary parties

-- Are there any non-root CA certs that could have been produced using an MD5
-- collision?
select Subject,Issuer,startdate 
from valid_certs 
where locate("TRUE", `X509v3 extensions:X509v3 Basic Constraints:CA`) 
  and `Signature Algorithm`=" md5WithRSAEncryption"
  and Subject!=Issuer;

-- There are two; neither of them looks like a dupe of another CA Subject

-- This is kind of bad though: there's quite a hierarchy beneath them:

select name, valid_certs.Issuer, `X509v3 extensions:X509v3 Basic Constraints:CA`
from (names join valid_certs)
     join  (
  select subject
  from valid_certs 
  where locate("TRUE", `X509v3 extensions:X509v3 Basic Constraints:CA`) 
    and `Signature Algorithm`=" md5WithRSAEncryption"
    and Subject!=Issuer
) as suspicious
on valid_certs.issuer=suspicious.subject;

select valid_certs.Issuer, `X509v3 extensions:X509v3 Basic Constraints:CA`
from valid_certs     join  (
  select subject
  from valid_certs 
  where locate("TRUE", `X509v3 extensions:X509v3 Basic Constraints:CA`) 
    and `Signature Algorithm`=" md5WithRSAEncryption"
    and Subject!=Issuer
) as suspicious
on valid_certs.issuer=suspicious.subject;

