# Security Policy

This repository contains the 2earl identity service (login.2earl.com). It is private and proprietary.

## Reporting a vulnerability

Write to **legal@2earl.com** with "Security" in the subject. The same contact is published at
<https://2earl.com/.well-known/security.txt>. Please don't disclose it before it's fixed.

Include as much of the following as you can:

- affected endpoint, flow or component
- steps to reproduce or a proof of concept
- impact you believe it has

You will receive an acknowledgement after the report is reviewed.

## Scope

In scope: the code in this repository and its deployment at `login.2earl.com`: sign-in, the
authorization server, organizations, single sign-on, directory sync and the organization API.

Out of scope: denial-of-service through volumetric traffic, social engineering, and findings in
third-party services (Google, Cloudflare, GitHub).
