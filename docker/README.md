docker for network Sysrepo plugin.

## build dockerfile

```
$ docker build -t sysrepo/sysrepo-netopeer2:network -f Dockerfile .
```

## run dockerfile with supervisor

```
$ docker run -i -t --name sysrepo2 -p 830:830 --rm sysrepo/sysrepo-netopeer2:network
```

## run dockerfile without supervisor

```
$ docker run -i -t --name sysrepo -p 830:830 --rm sysrepo/sysrepo-netopeer2:network bash
$ ubusd &
$ rpcd &
$ sysrepod
$ sysrepo-plugind
$ netopeer2-server
```
