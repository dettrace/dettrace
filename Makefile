# Top-level Makefile to capture different actions you can take.
all: build tests

build:
	cd src && ${MAKE}
	cp src/dettrace bin/
	cp src/libdet.so lib/

tests: run-tests

build-tests:
	$(MAKE) -C ./test/unitTests/ all

run-tests: build build-tests
	$(MAKE) -C ./test/unitTests/ run

DOCKER_NAME=dettrace
# TODO: store version in one place in a file.
DOCKER_TAG=0.0.1

docker:
	docker build -t ${DOCKER_NAME}:${DOCKER_TAG} .

run-docker:
	docker run -it --privileged --cap-add=SYS_ADMIN ${DOCKER_NAME}:${DOCKER_TAG}

test-docker:
	docker run --privileged --cap-add=SYS_ADMIN ${DOCKER_NAME}:${DOCKER_TAG} python3 /detTrace/runTests.py

.PHONY: clean docker run-docker tests build-tests run-tests
clean:
	$(RM) src/dettrace
	make -C ./src/ clean
	make -C ./test/unitTests/ clean
