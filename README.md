# Selkie

Use Selkie to enforce seccomp rules in your code. Select the entitlements that your application needs and not the ones it doesn't need!

<p align="center">
    <img src="lurker.jpg" alt="drawing" width="600"/>
</p>


## How it works

<i>Seccomp</i> is a security facility of the Linux kernel. It allows you to create filters for system calls on a process by process basis. For example, you can create a seccomp filter that would allow all system calls except for [chmod](http://man7.org/linux/man-pages/man2/fchmod.2.html). You can then load that filter into a running process. If the `chmod` system call is then used the kernel would return an error to your process which can handle it however it's programmed to.

Despite the power that seccomp provides, it's very difficult to use in practice. You must have deep knowledge of all system calls, and even then the task is daunting. This is where Selkie comes in.

<i>Selkie</i> uses entitlements to abstract away the need to know all the system calls your application will need. Getting started is as simple as familiarizing yourself with the entitlements Selkie offers.

## Entitlements

See godoc [here]()

## Dependencies

- libseccomp-dev [debian-like](https://launchpad.net/ubuntu/+source/libseccomp) / [centos-like](https://rpmfind.net/linux/rpm2html/search.php?query=libseccomp-devel)

## Quick Start

WIP
