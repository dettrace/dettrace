# Top-level Makefile to capture different actions you can take.
all: build

build: bin initramfs
	cd src && ${MAKE}
	rm -rf bin/dettrace
	cp src/dettrace bin/
	cp src/libdet.so lib/

bin:
	mkdir -p ./bin

static: bin
	cd src && ${MAKE} all-static
	rm -rf bin/dettrace
	cp src/dettrace-static bin/dettrace
	cp src/libdet.so lib/

templistfile := $(shell mktemp)
initramfs: initramfs.cpio
initramfs.cpio: root
	@cd root && find . > $(templistfile) && cpio -o > ../initramfs.cpio < $(templistfile) 2>/dev/null
	@$(RM) $(templistfile)

tests: run-tests
test: tests

build-tests:
	$(MAKE) -C ./test/unitTests/ build
	$(MAKE) -C ./test/samplePrograms/ build

run-tests: build-tests build
	$(MAKE) -C ./test/unitTests/ run
# NB: MAKEFLAGS= magic causes samplePrograms to run sequentially, which is
# essential to avoid errors with bind mounting a directory simultaneously
	MAKEFLAGS= make --keep-going -C ./test/samplePrograms/ run

DOCKER_NAME=dettrace
# TODO: store version in one place in a file.
DOCKER_TAG=0.0.1

docker:
	docker build -t ${DOCKER_NAME}:${DOCKER_TAG} .

run-docker: docker
	docker run -it --privileged --cap-add=SYS_ADMIN ${DOCKER_NAME}:${DOCKER_TAG}

test-docker: clean docker
	docker run --privileged --cap-add=SYS_ADMIN ${DOCKER_NAME}:${DOCKER_TAG} make -j tests

.PHONY: clean docker run-docker tests build-tests run-tests initramfs
clean:
	$(RM) src/dettrace
	make -C ./src/ clean
	make -C ./test/unitTests/ clean
	make -C ./test/samplePrograms/ clean
