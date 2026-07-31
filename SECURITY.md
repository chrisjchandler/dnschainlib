# Security Policy

## Supported Versions

This repo is maintained on a best-effort basis.

If I fix a security issue, assume the fix will land in:
- the latest tagged release
- the current `main` branch

Older versions may not get patched.

## Reporting a Vulnerability

If you find a security issue open a public GitHub issue for it.


Helpful things to include:
- what the issue is
- which version, tag, or commit you tested
- how to reproduce it
- sample input, if relevant
- logs or proof-of-concept details
- what kind of impact you think it has

I’ll look at reports as time allows.

## What kinds of issues matter here

This library does network lookups and enrichment, including:
- DNS lookups
- RIPEstat lookups
- public GeoIP lookups
- WHOIS lookups

So the kinds of reports I care most about are things like:
- network behavior happening when it shouldn’t
- input handling that can be abused or causes unsafe lookups
- denial-of-service style issues from bad or hostile input
- sensitive data showing up in output or logs when it shouldn’t
- dependency bugs that have a real effect on this library
- behavior that becomes risky when this package is embedded in bigger systems

## What probably doesn’t belong here

These usually aren’t security issues by themselves:
- DNS / WHOIS / GeoIP / ASN data being incomplete or wrong
- rate limits or outages from upstream services
- normal differences in what external services return
- problems caused only by how another application uses this library’s output

