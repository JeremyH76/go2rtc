# Go2rtc fork

To see initial README.md : https://github.com/AlexxIT/go2rtc

## Changes with the go2rtc repos

- README.md
- Add insecure cipher suites for Axis cameras #1
- feat(api): add support for CORS preflight requests #2

## Generate a new image and push it on Docker Hub

`docker build -f ./docker/Dockerfile -t jeremyh76/go2rtc:1.9.14.1 .`
Where the version is the go2rtc official last release, followed by subversion (.1 here) (optionnal)

`docker login`
Ask JeremyH76 for permissions.

`docker push jeremyh76/go2rtc:1.9.14.1`

See your image on : https://hub.docker.com/repository/docker/jeremyh76/go2rtc/general
