all:
	cd hiredis; make static; cd ..;
	apxs -c -i -A src/mod_doupre.c hiredis/libhiredis.a

clean:
	cd hiredis; make clean; cd ..;
	rm -rf src/.libs/ src/mod_doupre.la src/mod_doupre.lo src/mod_doupre.o src/mod_doupre.slo
