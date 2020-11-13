CC=g++
FLAGS=-g -Wall -pedantic -std=c++11
FILE=dns_filter

all:
	$(CC) $(FLAGS) -o ${FILE} main.cpp ErrorExceptions.h DNS_Filter.cpp DNS_Filter.h common.h common.cpp DomainLookup.cpp DomainLookup.h
	rm -rf *.gch 
	
clean:
	rm -rf *.gch ${FILE}