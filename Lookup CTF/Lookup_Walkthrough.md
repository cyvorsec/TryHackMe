LOOKUP CTF WALKTHROUGH

# 1. Enumeration

Add `Machine_IP lookup.thm` to /etc/hosts file.

```shell
sudo vim /etc/hosts
```

We will use ***NMAP*** to enumerate open ports on the target machine (we can also use ***Rustscan***).

```shell
sudo nmap -sS -T4 -vv -p- lookup.thm
```

We get two open ports: `SSH` and `HTTP`.

```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

Now we will check for port version, common scripts and OS information:

```shell
sudo nmap -sV -sC -O -T4 -vv -p 22,80 lookup.thm
```



