
# Top-level Makefile to capture different actions you can take.


build:
	cd src && ${MAKE}

DOCKER_NAME=dettrace
# TODO: store version in one place in a file.
DOCKER_TAG=0.0.1

docker:
	docker build -t ${DOCKER_NAME}:${DOCKER_TAG} .

run-docker:
	docker run -it ${DOCKER_NAME}:${DOCKER_TAG}
