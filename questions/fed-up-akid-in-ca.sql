select path,`X509v3 extensions:X509v3 Authority Key Identifier` 
from valid_certs
where length(`X509v3 extensions:X509v3 Authority Key Identifier`) < 100;

