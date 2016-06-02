Allgemeine Lösung zum Beleg zum Modul Informationssicherheit SS16
===============

Anforderungen
------------

Code ist nach C11 und POSIX Standard geschrieben, benötigt wird außerdem die OpenSSL Lib.

Cipher must be wrote like DES-EDE-CBC, so EVP_des_ede_cbc = DES-EDE-CBC for flag -c, or like dsaWithSHA for EVP_DSS

