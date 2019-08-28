NAME=cloudseal-alpha
VERSION=0.1.651
BUILDID=1

PKGNAME=${NAME}_${VERSION}-${BUILDID}

# Top-level Makefile to capture different actions you can take.
all: build

build: bin initramfs
	rm -rf bin/dettrace
	cd src && ${MAKE}
	cp src/dettrace bin/

bin:
	mkdir -p ./bin

static: bin initramfs
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

DOCKER_NAME=${NAME}
DOCKER_TAG=${VERSION}

docker:
	docker build -t ${DOCKER_NAME}:${DOCKER_TAG} -t ${DOCKER_NAME}:latest .
	docker run -i --rm --workdir /usr/share/cloudseal ${DOCKER_NAME}:${DOCKER_TAG} tar cf - . | bzip2 > cloudseal_alpha_pkg_${DOCKER_TAG}.tbz
	docker run -i --rm --workdir /usr/share/cloudseal ${DOCKER_NAME}:${DOCKER_TAG} cat "/root/${PKGNAME}.deb" > "${PKGNAME}.deb"

run-docker:
	mkdir -p /tmp/out
	rm -rf /tmp/out/*
	docker run --rm -it --privileged -v "/tmp/out:/out" ${DOCKER_NAME}:${DOCKER_TAG}

test-docker: docker
ifdef DETTRACE_NO_CPUID_INTERCEPTION
	docker run --rm --privileged --env DETTRACE_NO_CPUID_INTERCEPTION=1 ${DOCKER_NAME}:${DOCKER_TAG} true
else
	docker run --rm --privileged ${DOCKER_NAME}:${DOCKER_TAG} true
endif

.PHONY: clean docker run-docker tests build-tests run-tests initramfs deb
clean:
	$(RM) bin/dettrace
	$(RM) src/dettrace
	$(RM) -rf -- "${PKGNAME}" *.deb
	make -C ./src/ clean
# Use `|| true` in case one forgets to check out submodules
	make -C ./test/samplePrograms clean || true
	make -C ./test/standalone clean || true
	make -C ./test/unitTests clean || true

${PKGNAME}.deb: static
	./ci/create_deb.sh "${NAME}" "${VERSION}-${BUILDID}"

deb: ${PKGNAME}.deb
