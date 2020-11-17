CC=g++
FLAGS=-g -Wall -pedantic -std=c++11
FILE=dns

all:
	$(CC) $(FLAGS) -o ${FILE} main.cpp ErrorExceptions.h DNSFilter.cpp DNSFilter.h logger.h logger.cpp DomainLookup.cpp DomainLookup.h

clean:
	rm -rf *.gch ${FILE} test_DL test_DNSF *.tar

tar:
	cp ./doc/ISA_doc.pdf ./manual.pdf
	tar -cvf xmusko00.tar README.md manual.pdf Makefile main.cpp ErrorExceptions.h DNSFilter.cpp DNSFilter.h logger.h logger.cpp DomainLookup.cpp DomainLookup.h test_DomainLookup.cpp test_DNSFilter.cpp ./test_nslookup.sh

test:
	$(CC) $(FLAGS) -o ${FILE} main.cpp ErrorExceptions.h DNSFilter.cpp DNSFilter.h logger.h logger.cpp DomainLookup.cpp DomainLookup.h
	$(CC) $(FLAGS) -o test_DL test_DomainLookup.cpp DomainLookup.cpp DomainLookup.h ErrorExceptions.h
	$(CC) $(FLAGS) -o test_DNSF test_DNSFilter.cpp ErrorExceptions.h DNSFilter.cpp DNSFilter.h logger.h logger.cpp DomainLookup.cpp DomainLookup.h
	./test_DL 
	./test_DNSF
	bash ./test_nslookup.sh