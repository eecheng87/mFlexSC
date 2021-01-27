# mFlexSC

This project try to rework experiment done in [paper: FlexSC](https://www.usenix.org/legacy/events/osdi10/tech/full_papers/Soares.pdf). There're two main strategies and implemented in this project: batching system call and M-N threading.

## Build
build kernel module `mFlexsc`
```shell
cd module
sudo make
make ins
```
use testing program
```
cd user
make
./app
```
If FlexSC applied, need to config(define) `FLEXSC` in `app.c`. Otherwise, normal system call doesn't need to config anything.

## Overview
![](https://i.imgur.com/Od7V5hw.png)

Each kernel visible thread bound in specific CPU, in this project, bound in CPU0 and CPU1. There're several user level threads belong to those CPU and storing information(system call number and its arguments) about request into syscall page. Syscall page is shared memory between kernel space and user space, both can access the information on it. In kernel space, there is a scanner thread ceaselessly searching available entry. If found available(submitted) status, kernel work thread start calling system call requested in user space.

## Experiment
There're some experiments I made under `/expriment` and it seems that FlexSC get better porformance than normal system call.
![](https://i.imgur.com/eJb0hM7.png)