---
title: CRTP Review
weight: 1
tags:
    - CRTP
    - Review
    - CRTP Review
---

## Setting the Stage
I recently sat for the Certified Red Team Professional (CRTP) exam by Pentester Academy. I’ve read plenty of reviews from people who bought the 90-day lab access and spent weeks agonizing over the preparation. I took a different approach: I grabbed the 30-day lab access, dove straight in, and honestly found the whole experience to be a breeze.

<div align="center">
  <img src="/images/certs/crt_CRTP.png" alt="CRTP Certificate" width="80%" />
</div>

Here are my unfiltered thoughts on the course, the labs, and how I knocked out the exam and report in a single afternoon.

## Course Material & The Missing Pieces
The course heavily focuses on assumed-breach Active Directory enumeration and exploitation using purely Windows tools and PowerShell. Nikhil Mittal does a good job walking you through the attack chain, covering:

- Domain enumeration
- Local privilege escalation
- Lateral movement
- Domain persistence
- Domain privilege escalation
- Cross forest attacks
- Forest persistence

While learning the raw PowerShell mechanics is great for understanding the fundamentals of AD misconfigurations, I felt the curriculum was missing a crucial modern element: Command and Control (C2) frameworks. In modern red teaming, you aren't just firing raw PowerShell scripts from a single pivot machine. Including some basic C2 infrastructure would have made the labs feel much more realistic and up-to-date.

## The Exam Execution

### The Setup
Starting the exam is simple. You hit a button, wait about 15 minutes for the environment to build, and you get 25 hours to compromise a multi-domain environment. There’s no proctoring, which is always a plus. One thing to note is that the student VM is barebones—you are responsible for bringing and uploading your own tools.

### Flawless Execution
Unlike some folks who hit a wall and need to take a break for an "epiphany," my run was incredibly smooth. Because the attack paths heavily rely on standard AD misconfigurations rather than complex exploit chains, efficient enumeration is all you need. Once I had BloodHound, the path to compromising the domains was glaringly obvious.

### Game Over
I didn't hit any major roadblocks. I moved systematically through the target machines, grabbed the flags, and achieved the required access with hours and hours to spare on the clock.


## The Write-Up
I didn't need to sleep on it before starting my report. Because the exploitation phase was so quick and my notes were organized, I rolled right into the documentation phase. Writing the post-engagement report was just as straightforward as the exam itself.

## The Final Verdict
My total time from clicking "Start Exam" to submitting the final report was exactly 7 hours.

Overall, the CRTP is a solid introductory certification for Active Directory exploitation. It forces you to understand Windows internals and PowerShell, which is inherently valuable. However, if you already have some pentesting experience under your belt, expect this to be a very quick win.