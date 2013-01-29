all: clean afcgi

afcgi: afcgi.o fastcgi.o
	gcc -g -O2 -o afcgi afcgi.o fastcgi.o

afcgi.o:
	gcc -g -O2 -c afcgi.c

fastcgi.o:
	gcc -g -O2 -c fastcgi.c

clean:
	rm -f *.o afcgi
