# Top-level Makefile to capture different actions you can take.
all: build

build:
	cd src && ${MAKE}
	cp src/dettrace bin/
	cp src/libdet.so lib/

tests: run-tests

build-tests:
	$(MAKE) -C ./test/unitTests/ build
	$(MAKE) -C ./test/samplePrograms/ build

run-tests: build-tests build
	$(MAKE) -C ./test/unitTests/ clean
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

test-docker: docker
	docker run --privileged --cap-add=SYS_ADMIN ${DOCKER_NAME}:${DOCKER_TAG} make -j tests

.PHONY: clean docker run-docker tests build-tests run-tests
clean:
	$(RM) src/dettrace
	make -C ./src/ clean
	make -C ./test/unitTests/ clean
	make -C ./test/samplePrograms/ clean
