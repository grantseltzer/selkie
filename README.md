# Selkie

<p align="center">
    <b>Use Selkie to enforce seccomp rules in your code. Select the entitlements that your application needs and not the ones it doesn't need!</b>
</p>

## How it works

<i>Seccomp</i> is a security facility of the Linux kernel. It allows you to create filters for system calls on a process by process basis. For example, you can create a seccomp filter that would allow all system calls except for [chmod](http://man7.org/linux/man-pages/man2/fchmod.2.html). You can then load that filter into a running process. If the `chmod` system call is then used the kernel would return an error to your process which can handle it however it's programmed to.

Despite the power that seccomp provides, it's very difficult to use in practice. You must have deep knowledge of all system calls, and even then the task is daunting. This is where Selkie comes in.

<i>Selkie</i> uses entitlements to abstract away the need to know all the system calls your application will need. Getting started is as simple as familiarizing yourself with the entitlements Selkie offers.

Selkie's entitlements aren't quite allow or deny lists. The installed seccomp filter has a default action of 'Allow'. Meaning any unspecified system call in the filter will be allowed. On top of that, any Selkie entitlement that is not specified will be Denied. This is to avoid superfluous blocking of obscure/harmless system calls.

## Entitlements

See godoc [here](https://godoc.org/github.com/grantseltzer/selkie/go/pkg/entitlements)

## Dependencies

- libseccomp-dev [debian-like](https://launchpad.net/ubuntu/+source/libseccomp) / [centos-like](https://rpmfind.net/linux/rpm2html/search.php?query=libseccomp-devel)

## Quick Start

Let's say you're writing a simple HTTP webserver in go:

```
package main

import (
    "fmt"
    "net/http"
)

func main() {
    http.HandleFunc("/", HelloServer)
    http.ListenAndServe(":8080", nil)
}

func HelloServer(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "I can modprobe if you exploit me, %s!", r.URL.Path[1:])
}
```

This program just handles incoming HTTP requests on a network sockets. I didn't include anything exploitable here for simplicity but try to imagine the possibility of an application vulnerablity. 

The only relevant sounding entitlement is `NetworkConnection`. Let's apply it:


```
package main

import (
    "fmt"
    "net/http"
    selkie "github.com/grantseltzer/selkie/go/pkg/entitlements"
)

func main() {

    neededEntitlements := []selkie.Entitlement{
        "NetworkConnection"
    }

    err := selkie.ApplyEntitlements(neededEntitlements)
    if err != nil {
        log.Fatal(err)
    }

    http.HandleFunc("/", HelloServer)
    http.ListenAndServe(":8080", nil)
}

func HelloServer(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "I can modprobe if you exploit me, %s!", r.URL.Path[1:])
}
```
