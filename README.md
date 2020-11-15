# ISA - DNS FILTER

#### Popis
UDP Server filtrující dns pořadavky.

#### Rozšíření / Omezení
Je implementován verbose mode.


#### Příklad Spuštění
```
./dns -s 1.1.1.1 -p 1234 -f filter.example -v
```

#### Návratové kódy
 * 0 OK
 * 1 špatné argumenty
 * 2 nelze otevˇrít filtrovací soubor
 * 3 problém se soketem
 * 4 nelze přeložit IP adresu, nebo doménové jméno

#### Seznam odevzdaných souborů
 * main.cpp 
 * ErrorExceptions.h 
 * DNSFilter.cpp DNSFilter.h 
 * DomainLookup.cpp DomainLookup.h
 * logger.h logger.cpp 
 * test_DNSFilterp.cpp
 * test_DomainLookup.cpp
 * manual.pdf
