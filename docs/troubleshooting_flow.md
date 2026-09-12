# Troubleshooting Flow

This guide helps you decide which script to run first.

## Start With Symptoms

Before changing settings, identify what works and what fails.

Run:

```bat
scripts\check_network.bat
```

The diagnostic script checks:

- Direct internet reachability with `ping 8.8.8.8`
- DNS resolution with `nslookup google.com`
- HTTP access with `curl http://example.com`
- WinHTTP proxy settings
- User-level proxy registry values

## Flowchart-Style Steps

```text
Network problem starts
        |
        v
Run check_network.bat
        |
        v
Does ping 8.8.8.8 work?
        |
        +-- No --> Check Wi-Fi/Ethernet, router, adapter status, or ISP connection
        |
        +-- Yes
              |
              v
Does nslookup google.com work?
              |
              +-- No --> Run reset_dns.bat
              |
              +-- Yes
                    |
                    v
Does curl http://example.com work?
                    |
                    +-- Yes --> Basic network path is working
                    |
                    +-- No
                          |
                          v
Are proxy settings enabled or suspicious?
                          |
                          +-- Yes --> Run reset_proxy.bat
                          |
                          +-- No
                                |
                                v
Run one_click_fix.bat as Administrator
                                |
                                v
Restart Windows
```

## Why This Order Works

Each step tests a different layer:

- Ping checks basic IP connectivity.
- DNS checks whether names can be converted to IP addresses.
- `curl` checks whether HTTP traffic works.
- Proxy checks catch settings that can break browsers and command-line tools.
- Winsock and TCP/IP resets repair deeper Windows networking problems.

## When To Use The Full Repair

Use `one_click_fix.bat` when:

- Ping works but browser traffic fails.
- Proxy settings keep coming back or look wrong.
- DNS flush alone did not help.
- Network problems started after VPN, proxy, malware cleanup, or security software changes.
- Multiple apps fail in different ways.

After running the full repair, restart Windows.
