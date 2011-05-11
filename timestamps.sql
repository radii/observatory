-- These commands add additional database columns of the correct type, based
-- on generic string data in legacy columns.

alter table all_certs add column startdate datetime;
alter table all_certs add column enddate datetime;
alter table valid_certs add column startdate datetime;
alter table valid_certs add column enddate datetime;

update all_certs
  set startdate=STR_TO_DATE(`Validity:Not Before`, '%b %d %H:%i:%s %Y'),
        enddate=STR_TO_DATE(`Validity:Not After`,  '%b %d %H:%i:%s %Y');

update valid_certs
  set startdate=STR_TO_DATE(`Validity:Not Before`, '%b %d %H:%i:%s %Y'),
        enddate=STR_TO_DATE(`Validity:Not After`,  '%b %d %H:%i:%s %Y');

alter table all_certs add column `Validity:Not Before datetime` datetime;
alter table all_certs add column `Validity:Not After datetime` datetime;
alter table valid_certs add column `Validity:Not Before datetime` datetime;
alter table valid_certs add column `Validity:Not After datetime` datetime;

update all_certs
  set `Validity:Not Before datetime`=STR_TO_DATE(`Validity:Not Before`, '%b %d %H:%i:%s %Y'),
        `Validity:Not After datetime`=STR_TO_DATE(`Validity:Not After`,  '%b %d %H:%i:%s %Y');

update valid_certs
  set `Validity:Not Before datetime`=STR_TO_DATE(`Validity:Not Before`, '%b %d %H:%i:%s %Y'),
        `Validity:Not After datetime`=STR_TO_DATE(`Validity:Not After`,  '%b %d %H:%i:%s %Y');

