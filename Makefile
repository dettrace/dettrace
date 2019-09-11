
NAME := cloudseal-alpha
# Version is currently based on number of git commits:
# TODO: store version in one place in a file.
VERSION := $(shell if [ -e version ]; then cat version; else echo "0.1."`git log --pretty=oneline | wc -l`; fi)
BUILDID := 1

PKGNAME := ${NAME}_${VERSION}-${BUILDID}

version: .git/index
	@echo Writing VERSION=$(VERSION) to file.
	echo $(VERSION) > $@

# Top-level Makefile to capture different actions you can take.
all: build

# Shorthand for `dynamic`.
build: dynamic

bin:
	mkdir -p ./bin

# This only builds a dynamically linked binary.
dynamic: bin initramfs
	rm -rf bin/dettrace
	cd src && ${MAKE}
	cp src/dettrace bin/

# This only builds a statically linked binary.
static: bin initramfs
	rm -rf bin/dettrace
	cd src && ${MAKE} all-static
	cp src/dettrace-static bin/dettrace-static

# This builds both a dynamically linked binary (named bin/dettrace)
# and a statically linked binary (named bin/dettrace-static)
dynamic-and-static: bin initramfs
	rm -rf bin/dettrace
	cd src && ${MAKE}
	cp src/dettrace bin/
	cd src && ${MAKE} all-static
	cp src/dettrace-static bin/dettrace-static

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
	$(RM) version
	$(MAKE) version
	docker build -t ${DOCKER_NAME}:${DOCKER_TAG} -t ${DOCKER_NAME}:latest .
	docker run -i --rm --workdir /usr/share/cloudseal ${DOCKER_NAME}:${DOCKER_TAG} tar cf - . | bzip2 > cloudseal_alpha_pkg_${DOCKER_TAG}.tbz
	docker run -i --rm --workdir /usr/share/cloudseal ${DOCKER_NAME}:${DOCKER_TAG} cat "/root/${PKGNAME}.deb" > "${PKGNAME}.deb"

DOCKER_RUN_ARGS=--rm --privileged --userns=host --cap-add=SYS_ADMIN ${OTHER_DOCKER_ARGS} ${DOCKER_NAME}:${DOCKER_TAG}

# For convenience, we create an output portal to produce example output:
run-docker:
	mkdir -p /tmp/out
	rm -rf /tmp/out/*
	docker run -v "/tmp/out:/out" ${DOCKER_RUN_ARGS} ${DOCKER_RUN_COMMAND}

run-docker-non-interactive: docker
	docker run ${DOCKER_RUN_ARGS} ${DOCKER_RUN_COMMAND}

test-docker: docker
ifdef DETTRACE_NO_CPUID_INTERCEPTION
	docker run --env DETTRACE_NO_CPUID_INTERCEPTION=1 ${DOCKER_RUN_ARGS} true
else
	docker run ${DOCKER_RUN_ARGS} make -j tests
endif

.PHONY: build clean docker run-docker tests build-tests run-tests initramfs deb docker-dev env
clean:
	$(RM) version
	$(RM) bin/dettrace
	$(RM) bin/dettrace-static
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

# Builds a docker image suitable for development.
docker-dev: Dockerfile.dev
	docker build \
		--build-arg "USER_ID=$(shell id -u)" \
		--build-arg "GROUP_ID=$(shell id -g)" \
		-t "${DOCKER_NAME}:dev" \
		-f $< .

# Runs a docker image suitable for development. Note that the container is run
# as the current user in order to avoid creating root-owned files in the volume
# mount.
env: docker-dev
	docker run \
		--rm \
		--privileged \
		-it \
		-v "$(shell pwd):/code" \
		-u "$(shell id -u):$(shell id -g)" \
		"${DOCKER_NAME}:dev" \
		bash
