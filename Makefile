# Name and version of the package. This should be the *only* place where these
# settings are modified.
NAME := dettrace
VERSION := 0.1.0
BUILDID := $(shell git rev-list --count HEAD 2> /dev/null || echo 0)

PKGNAME := ${NAME}_${VERSION}-${BUILDID}

.PHONY: \
	all \
	build \
	build-tests \
	clean \
	deb \
	docker \
	docker-dev \
	dynamic \
	env \
	install \
	run-docker \
	run-docker-non-interactive \
	run-tests \
	static \
	test-docker \
	tests

# Top-level Makefile to capture different actions you can take.
all: build

# Shorthand for `dynamic`.
build: dynamic

bin:
	mkdir -p ./bin

# This only builds a dynamically linked binary.
dynamic: bin/${NAME}
bin/${NAME}: bin
	cd src && ${MAKE}
	cp src/${NAME} bin/

# This only builds a statically linked binary.
static: bin/${NAME}-static
bin/${NAME}-static: bin
	cd src && ${MAKE} all-static
	cp src/${NAME}-static bin/

# This builds both a dynamically linked binary (named bin/${NAME}) and a
# statically linked binary (named bin/${NAME}-static)
dynamic-and-static: bin/${NAME} bin/${NAME}-static

tests: run-tests
test: tests

build-tests:
	$(MAKE) -C ./test/unitTests/ build
	$(MAKE) -C ./test/samplePrograms/ build

run-tests: build-tests build
	@echo "Running tests on this Linux platform:"
	uname -a
	cat /proc/cpuinfo | head -n 20
	$(MAKE) -C ./test/unitTests/ run
# NB: MAKEFLAGS= magic causes samplePrograms to run sequentially, which is
# essential to avoid errors with bind mounting a directory simultaneously
	MAKEFLAGS= make --keep-going -C ./test/samplePrograms/ run

# Build the system inside Docker.  This produces an image shippable to Dockerhub.
docker:
	docker build -t ${NAME}:${VERSION} .

DOCKER_RUN_ARGS=--rm --privileged --userns=host ${OTHER_DOCKER_ARGS} ${NAME}:${VERSION}

# Run the same image we built.
run-docker: docker
	docker run -it ${DOCKER_RUN_ARGS} ${DOCKER_RUN_COMMAND}

run-docker-non-interactive: docker
	docker run ${DOCKER_RUN_ARGS} ${DOCKER_RUN_COMMAND}

test-docker: clean docker
ifdef DETTRACE_NO_CPUID_INTERCEPTION
	docker run --env DETTRACE_NO_CPUID_INTERCEPTION=1 ${DOCKER_RUN_ARGS} make -j tests
else
	docker run ${DOCKER_RUN_ARGS} make -j tests
endif

clean:
	$(RM) -rf -- bin "src/${NAME}" "src/${NAME}-static" *.deb

	make -C ./src/ clean
	# Use `|| true` in case one forgets to check out submodules
	make -C ./test/samplePrograms clean || true
	make -C ./test/standalone clean || true
	make -C ./test/unitTests clean || true

# Build a Debian package.
deb: ${PKGNAME}.deb
${PKGNAME}.deb: bin/${NAME}-static ci/create_deb.sh
	./ci/create_deb.sh "${NAME}" "${VERSION}-${BUILDID}"

# Installs the Debian package.
install: ${PKGNAME}.deb
	sudo dpkg -i $^

# Builds a docker image suitable for development.
docker-dev: Dockerfile.dev
	docker build \
		--build-arg "USER_ID=$(shell id -u)" \
		--build-arg "GROUP_ID=$(shell id -g)" \
		-t "${NAME}:dev" \
		-f $< ci

# Runs a docker image suitable for development. Note that the container is run
# as the current user in order to avoid creating root-owned files in the volume
# mount.  
env: docker-dev
	docker run \
		--rm \
		--privileged \
		--userns=host \
		-it \
		-e DETTRACE_NO_CPUID_INTERCEPTION=1 \
		-v "$(shell pwd):/code" \
		-u "$(shell id -u):$(shell id -g)" \
		"${NAME}:dev" \
		bash
