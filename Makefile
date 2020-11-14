CC=g++
FLAGS=-g -Wall -pedantic -std=c++11
FILE=dns

all:
	$(CC) $(FLAGS) -o ${FILE} main.cpp ErrorExceptions.h DNS_Filter.cpp DNS_Filter.h common.h common.cpp DomainLookup.cpp DomainLookup.h
	rm -rf *.gch 

clean:
	rm -rf *.gch ${FILE} test_DL test_DNSF

tar:
	tar -cvf xmusko00.tar Makefile main.cpp ErrorExceptions.h DNS_Filter.cpp DNS_Filter.h common.h common.cpp DomainLookup.cpp DomainLookup.h

test:
	$(CC) $(FLAGS) -o test_DL test_DomainLookup.cpp DomainLookup.cpp DomainLookup.h ErrorExceptions.h
	$(CC) $(FLAGS) -o test_DNSF test_DNSFilter.cpp ErrorExceptions.h DNS_Filter.cpp DNS_Filter.h common.h common.cpp DomainLookup.cpp DomainLookup.h
	./test_DL 
	./test_DNSF