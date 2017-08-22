# hash-server

This program was developed and tested with Go 1.8 on Linux and Windows. The hash function seems to run considerably faster on Linux than on Windows.

To build, use this command:

```
go build hash-server.go
```

To run on Linux and listen on port 8080:

```
./hash-server 8080
```

and on Windows:

```
.\hash-server 8080
```

To gracefully shutdown type control-C or send a POST request to the URL ```/shutdown```, e.g.:

```
curl -X POST http://mysystem:8080/shutdown
```

On Linux, the server will also gracefully shutdown when sent ```SIGHUP```.
