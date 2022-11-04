# Docker images

This directory contains Docker images build context (build directories)
used by `framework.docker_server.DockerServer`.

## Usage example

```python
class Test(tester.TempestaTest):

    backends = [
        # Run `httpbin` image with default values
        {
            "id": "server-1",
            "type": "docker",
            "image": "httpbin",
            "ports": {8001: 8000},
        },
        # Run `python` image in privileged mode,
        # with overriden ENTRYPOINT and CMD,
        # pass environment variable TEXT
        {
            "id": "server-2",
            "type": "docker",
            "image": "python",
            "ports": {8002: 8000},
            "options": "--privileged",
            "entrypoint": "/bin/sh",
            "cmd_args": "-c 'while :; do yes $TEXT | nc -lkp 8000 ; done'",
            "env": {
               "TEXT": "test",
            },
        },
    ]
```

## Images list

### httpbin
HTTP Request & Response Service.

Provides endpoints with dynamic data, retry logic, streaming behavior, timeouts etc.

### python

Python 3.10 image.

To run backend server with a custom script,

  - place `new-script.py` to the `docker/python` directory,
  - and add `{"cmd_args: "new-script.py"}` to the backend declaration.

### wordpress

WordPress installation with generated blog data, proxied by the Apache server.

Special endpoints:

  - /?page_id=2 - small blog page
  - /?page_id=3 - blog page with long text
  - /empty.txt - empty file
  - /hello.txt - small file
  - /generated.php - generated content, 204800 of repeated '@'
  - /images.html - HTML page with one big and 3 small images
  - /images.php?n=10&max=2048 - HTML page with `n` random images with the maximum resolution `max`*`max`
  - /info.php - information about site PHP configuration
  - /wp-login.php - admin site login. Admin credentials is `admin`:`secret`

/images URI path provides images of different dimensions:

  - /images/2048.jpg - 2048x2048 image, about 9,9M size
  - ...
  - /images/128.jpg - 128x128 image, about 40K size

Available dimensions: 2048, 1920, 1792, 1664, 1536, 1408, 1280, 1152, 1024, 896, 768, 640, 512, 384, 256, 128.

## New Docker image

To add a new image, create a `NEW` subdirectory with the Dockerfile and all the files needed for build.
`NEW` is an image name to use in a backend declaration block: `{"type": "docker", "image": "NEW"}`.

Dockerfile should contain `HEALTHCHECK` declaration. For example, for permanently "healthy" results:
```
  HEALTHCHECK exit 0
```

## Run image manually

All built images has `tt-` prefix and can be used manually after the test run.
For example, to start WordPress on port 8001:
```bash
   docker run --rm -p 8001:80 \
   --env WP_HOME=http://127.0.0.1:8001 \
   --env WP_SITEURL=http://127.0.0.1:8001 \
   tt-wordpress
```
