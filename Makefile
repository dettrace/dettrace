# Name of the package. The version number should be modified in the VERSION
# file.
NAME := dettrace
VERSIONFILE= ./VERSION
DTVERSION := $(shell cat $(VERSIONFILE))
BUILDID := $(shell git rev-list --count HEAD 2> /dev/null || echo 0)

PKGNAME := $(NAME)_$(DTVERSION)-$(BUILDID)

# Compilation options
CXX := clang++
CC := clang
CLANG_TIDY := clang-tidy

DEFINES := -D_GNU_SOURCE=1 -D_POSIX_C_SOURCE=20181101 -D__USE_XOPEN=1 -DAPP_VERSION=\"$(DTVERSION)\" -DAPP_BUILDID=\"$(BUILDID)\"
INCLUDE := -I include -I cxxopts/include
CXXFLAGS += -g -O3 -std=c++14 -Wall $(INCLUDE) $(DEFINES)
CFLAGS += -g -O3 -Wall -Wshadow $(INCLUDE) $(DEFINES)
LIBS := -pthread -lseccomp

# Source files and objects to build.
src = $(wildcard src/*.cpp)
obj = $(src:.cpp=.o)
dep = $(obj:.o=.d)

.PHONY: \
	all \
	build \
	build-tests \
	check-formatting \
	clean \
	deb \
	docker \
	docker-dev \
	dynamic \
	env \
	fmt \
	format \
	install \
	run-docker \
	run-docker-non-interactive \
	run-tests \
	static \
	tarball \
	test-docker \
	tests

# Top-level Makefile to capture different actions you can take.
all:
	which $(CXX)
	$(CXX) --version
	$(MAKE) build

# Shorthand for `dynamic`.
build: dynamic

bin:
	mkdir -p bin

# This only builds a dynamically linked binary.
dynamic: bin/$(NAME)
bin/$(NAME): bin $(obj) $(VERSIONFILE)
	$(CXX) $(CXXFLAGS) $(obj) $(LIBS) -o $@

# This only builds a statically linked binary.
static: bin/$(NAME)-static
bin/$(NAME)-static: bin $(obj)
	$(CXX) $(CXXFLAGS) -static $(obj) $(LIBS) -o $@

# Compile the source files and generate a dep file at the same time so that
# incremental builds work (relatively) correctly.
src/%.o: src/%.cpp $(VERSIONFILE)
# Check if clang-tidy is installed. If not, skip formatting.
ifeq (, $(shell which $(CLANG_TIDY)))
	@echo "Skipping formating via clang-tidy"
else
	$(CLANG_TIDY) $< -- $(CXXFLAGS)
endif
	$(CXX) -c -MMD $(CXXFLAGS) $< -o $@

-include $(dep)

# This builds both a dynamically linked binary (named bin/$(NAME)) and a
# statically linked binary (named bin/$(NAME)-static)
dynamic-and-static: bin/$(NAME) bin/$(NAME)-static

tests: run-tests
test: tests

build-tests: check-formatting
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
	docker build -t "$(NAME):$(DTVERSION)" -t "$(NAME):latest" --build-arg "BUILDID=$(BUILDID)" .


tarball: ${NAME}_alpha_pkg_${DTVERSION}.tbz
${NAME}_alpha_pkg_${DTVERSION}.tbz: docker
	docker run -i --rm --workdir /usr/share/${NAME} "$(NAME):$(DTVERSION)" tar cf - . | bzip2 > ${NAME}_alpha_pkg_${DTVERSION}.tbz

DOCKER_RUN_ARGS=--rm --privileged --userns=host $(OTHER_DOCKER_ARGS) $(NAME):$(DTVERSION)

# Run the same image we built.
run-docker: docker
	docker run -it $(DOCKER_RUN_ARGS) $(DOCKER_RUN_COMMAND)

run-docker-non-interactive: docker
	docker run $(DOCKER_RUN_ARGS) $(DOCKER_RUN_COMMAND)

clean:
	$(RM) -rf -- bin *.deb
	$(RM) -- $(obj) $(dep)

	# Use `|| true` in case one forgets to check out submodules
	make -C ./test/samplePrograms clean || true
	make -C ./test/standalone clean || true
	make -C ./test/unitTests clean || true

# Build a Debian package.
deb: $(PKGNAME).deb
$(PKGNAME).deb: bin/$(NAME)-static ci/create_deb.sh $(VERSIONFILE)
	./ci/create_deb.sh "$(NAME)" "$(DTVERSION)-$(BUILDID)"

# Installs the Debian package.
install-deb: $(PKGNAME).deb
	sudo dpkg -i $^

install:
	@echo "Installing into DESTDIR="$(DESTDIR)
	mkdir -p $(DESTDIR)
	touch $(DESTDIR)/output_test
	cp -a bin root $(DESTDIR)

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
		--userns=host \
		-it \
		-e DETTRACE_NO_CPUID_INTERCEPTION=1 \
		-v "$(shell pwd):/code" \
		-u "$(shell id -u):$(shell id -g)" \
		"$(NAME):dev" \
		bash

# Formats the codebase using clang-format.
fmt: format
format:
	@find src -type f -name '*.cpp' -exec clang-format -i '{}' \+
	@find include -type f -name '*.hpp' -exec clang-format -i '{}' \+

# Checks the formatting on all files without actually modifying them. If
# formatting is incorrect, a diff is printed out.
check-formatting:
	@find src -type f -name '*.cpp' -print0 | xargs -0 -n1 ./ci/check-formatting.sh
	@find include -type f -name '*.hpp' -print0 | xargs -0 -n1 ./ci/check-formatting.sh

# Installs Git hooks.
hooks:
	rm -rf -- .git/hooks
	ln -sf ../.githooks .git/hooks

test-docker: clean docker-dev
	docker run \
                --rm \
                --privileged \
                --userns=host \
                -e DETTRACE_NO_CPUID_INTERCEPTION=1 \
                -v "$(shell pwd):/code" \
                -u "$(shell id -u):$(shell id -g)" \
                "$(NAME):dev" \
                make test CC=clang CXX=clang++ NAME=dettrace
