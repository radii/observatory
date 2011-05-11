select
  `X509v3 extensions:X509v3 Key Usage`,
  `X509v3 extensions:X509v3 Basic Constraints:CA`, 
  nid
from valid_certs
where 
  (locate("Certificate Sign", `X509v3 extensions:X509v3 Key Usage`)!=0)
    !=
  (locate("TRUE", `X509v3 extensions:X509v3 Basic Constraints:CA`)!=0);
