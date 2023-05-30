# sukkalaatikko

> (the sock box)

Sukkalaatikko proxies UNIX socket requests, like `socat` but not as powerful.

I've used it to debug what happens between the Docker client and the Docker daemon.

## Usage

```
uv run sukkalaatikko.py -p temp.sock -t /Users/akx/.docker/run/docker.sock
```

would create a UNIX socket at `temp.sock` that proxies requests to `/Users/akx/.docker/run/docker.sock`.

You can then do e.g. `set -x DOCKER_HOST unix:///Users/akx/temp.sock` and use the Docker client as usual.

Conversations are logged on stdout and in the `data/` directory in pcap and JSON formats.

