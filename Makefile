bin/detTrace:
	make -C src/ detTrace
	cp src/detTrace bin/

clean:
	rm bin/detTrace

.PHONY: clean
