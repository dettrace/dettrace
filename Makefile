# Name of the package. The version number should be modified in the VERSION
# file.
NAME := dettrace
VERSION := $(shell cat VERSION)
BUILDID := $(shell git rev-list --count HEAD 2> /dev/null || echo 0)

PKGNAME := $(NAME)_$(VERSION)-$(BUILDID)

# Compilation options
CXX := clang++
CC := clang
DEFINES := -D_GNU_SOURCE=1 -D_POSIX_C_SOURCE=20181101 -D__USE_XOPEN=1 -DAPP_VERSION=$(VERSION)
INCLUDE := -I include
CXXFLAGS := -g -O3 -std=c++14 -Wall $(INCLUDE) $(DEFINES)
CFLAGS := -g -O3 -Wall -Wshadow $(INCLUDE) $(DEFINES)
LIBS := -pthread -lseccomp

# Source files and objects to build.
src = $(wildcard src/*.cpp)
obj = $(src:.cpp=.o)
dep = $(obj:.o=.d)

obj += src/initramfs.o

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
	initramfs \
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
	mkdir -p bin

src/initramfs.o: src/initramfs.S initramfs.cpio
	$(CC) $< $(CFLAGS) -c -o $@ -D__INITRAMFS__='"initramfs.cpio"'

# This only builds a dynamically linked binary.
dynamic: bin/$(NAME)
bin/$(NAME): bin $(obj) VERSION
	$(CXX) $(CXXFLAGS) $(obj) $(LIBS) -o $@ \
		$(shell pkg-config --libs libarchive) \
		$(shell pkg-config --libs libcrypto)

# This only builds a statically linked binary.
static: bin/$(NAME)-static
bin/$(NAME)-static: bin $(obj)
	$(CXX) $(CXXFLAGS) -static $(obj) $(LIBS) -o $@ \
		$(shell pkg-config --static --libs libarchive) \
		$(shell pkg-config --static --libs libcrypto)

# Compile the source files and generate a dep file at the same time so that
# incremental builds work (relatively) correctly.
src/%.o: src/%.cpp VERSION
	$(CXX) -c -MMD $(CXXFLAGS) $< -o $@

-include $(dep)

# This builds both a dynamically linked binary (named bin/$(NAME)) and a
# statically linked binary (named bin/$(NAME)-static)
dynamic-and-static: bin/$(NAME) bin/$(NAME)-static

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

docker:
	docker build -t "$(NAME):$(VERSION)" -t "$(NAME):latest" --build-arg "BUILDID=$(BUILDID)" .

DOCKER_RUN_ARGS=--rm --privileged --userns=host $(OTHER_DOCKER_ARGS) $(NAME):$(VERSION)

run-docker: docker
	docker run -it $(DOCKER_RUN_ARGS) $(DOCKER_RUN_COMMAND)

run-docker-non-interactive: docker
	docker run $(DOCKER_RUN_ARGS) $(DOCKER_RUN_COMMAND)

test-docker: clean docker
ifdef DETTRACE_NO_CPUID_INTERCEPTION
	docker run --env DETTRACE_NO_CPUID_INTERCEPTION=1 $(DOCKER_RUN_ARGS) make -j tests
else
	docker run $(DOCKER_RUN_ARGS) make -j tests
endif

clean:
	$(RM) -rf -- bin *.deb
	$(RM) -- $(obj) $(dep)

	# Use `|| true` in case one forgets to check out submodules
	make -C ./test/samplePrograms clean || true
	make -C ./test/standalone clean || true
	make -C ./test/unitTests clean || true

# Build a Debian package.
deb: $(PKGNAME).deb
$(PKGNAME).deb: bin/$(NAME)-static ci/create_deb.sh VERSION
	./ci/create_deb.sh "$(NAME)" "$(VERSION)-$(BUILDID)"

# Installs the Debian package.
install: $(PKGNAME).deb
	sudo dpkg -i $^

# Builds a docker image suitable for development.
docker-dev: Dockerfile.dev
	docker build \
		--build-arg "USER_ID=$(shell id -u)" \
		--build-arg "GROUP_ID=$(shell id -g)" \
		-t "$(NAME):dev" \
		-f $< ci

# Runs a docker image suitable for development. Note that the container is run
# as the current user in order to avoid creating root-owned files in the volume
# mount.
env: docker-dev
	docker run \
		--rm \
		--privileged \
		-it \
		-e DETTRACE_NO_CPUID_INTERCEPTION=1 \
		-v "$(shell pwd):/code" \
		-u "$(shell id -u):$(shell id -g)" \
		"$(NAME):dev" \
		bash
