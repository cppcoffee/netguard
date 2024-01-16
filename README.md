# NetGuard

## Introduction

A layer 4 Single Packet Authentication (SPA) Server, used to conceal TCP/UDP ports on public facing machines and add an extra layer of security.

## Project structure

`netguard-server`: SPA service program responsible for authenticating knock packets and connection tracking.

`netguard-tool`: generate signing certificates, generate and send knock packets.

### Source code directory

```
.
├── Makefile        # convenient compilation
├── crypto          # encryption and decryption crate
│   ├── Cargo.toml
│   └── src
├── server          # netguard-server implement
│   ├── Cargo.toml
│   ├── config      # config file used for running netguard-server
│   └── src
└── tool            # netguard-tool implement
    ├── Cargo.toml
    └── src
```

## Basic Usage

### Run server protection ports

Run `netguard-server` on the server side to hide tcp port 10022:

```shell
$ netguard-server -c ./netguard.toml
```

### Run knock tool

On client site, Using `netguard-tool` to send knock packets:

```shell
$ sudo ./netguard-tool auth --server 45.76.195.141 --protocol=tcp --unlock 10022 --key=./rsa_key
```

### Example

Two devices, one listening on port 10022 and then taken over by `netguard-server`:

![image](https://github.com/cppcoffee/netguard/blob/main/img/example.png?raw=true)


### Generating an Key Pair Manually

Generating an RSA Key Pair with Default Options:

```shell
$ netguard-tool keygen
```

The parameters for the default option are equivalent to: `netguard-tool keygen -a rsa -b 4096 -o .netguard/rsa`

More parameter help:

```shell
$ netguard-tool keygen --help
```


### Reload config

Reload `netguard-server` config file:

```shell
$ pkill -HUP netguard-server
```


## Build

Build release version.

```shell
$ make release
```

or

```shell
$ cargo build --release
```

## TODO

- Add query and reject connection Interfaces
- More certificate signing algorithms
- Hot update bin executable program
- Audit log
- Knock SDK APIs

## Reference

- [https://www.netfilter.org/](https://www.netfilter.org/)
- [https://github.com/landhb/DrawBridge](https://github.com/landhb/DrawBridge)

