# Top-level Makefile to capture different actions you can take.
all: build

build: bin initramfs
	rm -rf bin/dettrace
	cd src && ${MAKE}
	cp src/dettrace bin/

bin:
	mkdir -p ./bin

static: bin
	rm -rf bin/dettrace
	cd src && ${MAKE} all-static
	cp src/dettrace-static bin/dettrace

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
	cat /proc/cpuinfo
	uname -a
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
	docker run --rm -it --privileged --cap-add=SYS_ADMIN ${DOCKER_NAME}:${DOCKER_TAG}

test-docker: clean docker
ifdef DETTRACE_NO_CPUID_INTERCEPTION
	docker run --rm --privileged --cap-add=SYS_ADMIN --env DETTRACE_NO_CPUID_INTERCEPTION=1  ${DOCKER_NAME}:${DOCKER_TAG} make -j tests
else
	docker run --rm --privileged --cap-add=SYS_ADMIN ${DOCKER_NAME}:${DOCKER_TAG} make -j tests
endif

.PHONY: clean docker run-docker tests build-tests run-tests initramfs
clean:
	$(RM) src/dettrace
	make -C ./src/ clean
	# Use `|| true` in case one forgets to check out submodules
	make -C ./test/samplePrograms clean || true
	make -C ./test/standalone clean || true
	make -C ./test/unitTests clean || true
