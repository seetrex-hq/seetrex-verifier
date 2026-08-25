# Security Policy

## Reporting a vulnerability

Email **security@seetrex.com**.

That address is the single point of contact designated under Article 13(17) of
Regulation (EU) 2024/2847 (the Cyber Resilience Act), and the mailbox has been
in service since **2026-08-25**. We acknowledge every report within 3 business
days. If email does not suit you, say so in a first message and we will agree
another means of communication with you: Article 13(17), third subparagraph,
requires the single point of contact to allow users to choose their preferred
means of communication and not to limit such means to automated tools.

Please do not open a public issue for a security problem. Use the address
above and give us the coordination window described below.

A useful report says what the problem is, which crate, version, commit or URL
it affects, and how to reproduce it. Proof-of-concept code, logs and
screenshots help. Write in English or Spanish, whichever you prefer.

Two URLs are the canonical locations for this policy on the web: the
machine-readable form of the contact belongs at
<https://seetrex.com/.well-known/security.txt> (RFC 9116), and the full
coordinated vulnerability disclosure policy at <https://seetrex.com/security>.
Said plainly, because this file is not the place to overstate: both of those
paths are not yet live. The deployment that would serve them from the apex has
not happened, so today they answer with the site shell and not with the policy.
**Until that deployment lands, the text in this file is the policy that
governs.** When it lands, the page at <https://seetrex.com/security> becomes the
authoritative copy, this file stays the copy that travels with the source, and
if the two ever disagree the page wins.

## Scope of this repository

This repository holds the open half of Seetrex Compliance: the verdict package
format, the offline verifier, the auditor CLI and the published specification.
Vulnerabilities in that code are in scope, and so is anything that could make a
verifier report a verdict as valid when it is not, or as invalid when it is.

Vulnerabilities in the hosted services (seetrex.com, compliance.seetrex.com,
trust.seetrex.com and the customer portal) are covered by the same policy and
the same address. So is the release-signing key material, and the integrity of
anything we publish for download.

Out of scope: findings that require physical access to our premises, social
engineering of our people, denial of service by volume, and reports produced
only by an automated scanner with no demonstrated impact. Third-party services
we merely consume are in scope only for the part we control — tell us anyway and
we will route the report to the vendor.

## What we do, and when

- **Acknowledgement within 3 business days** of your report reaching the
  address above.
- **An initial assessment within 10 business days**: whether we reproduce it,
  how we rate its severity, and what we intend to do.
- **Progress updates at least every 15 calendar days** until the report is
  closed.
- **We fix without delay internally**, prioritised by severity. That is a
  commitment about our own work, not a promise about when the fix reaches you:
  delivery is a separate question, and today it is the part that is not in
  place — see «Security updates» below for what exists and what does not. Where
  the vulnerability reaches a component we did not write, we report it upstream
  to whoever maintains it and share the fix with them (Article 13(6)).

## Coordinated disclosure

We ask you to keep the details private for **90 calendar days** from your first
report, or until a fix is publicly available, whichever comes first. If we need
longer, we will say so and explain why, and we will agree an extension with you
rather than announce one. If we fail to respond, you are released from this
request: a reporter should never be trapped by our silence.

We are happy to credit you by name in the advisory. Tell us how you want to be
named, or that you prefer not to be.

## Safe harbour

If you make a good-faith effort to comply with this policy, we will treat your
research as authorised, will not initiate or support legal action against you
over it, and will say so to any third party who asks.

Good faith means: only your own accounts and data, or data you are entitled to
access; no destruction, modification or exfiltration of anyone else's data; no
degradation of the service for others; stopping as soon as you have proved the
point; and telling us before you tell anyone else. If a law or a contract with
a third party leaves you in doubt, ask us first. We would rather answer the
question than lose the report.

## Disclosure of fixed vulnerabilities

Once a security update is available, we publish an advisory containing a
description of the vulnerability, the information needed to identify which
product and versions are affected, its impact, its severity, and clear
instructions for remediating it (Annex I, Part II, point (4) of the
Regulation). Advisories will be published on the policy page. No security
advisory has been issued to date.

Where publishing would put users at greater risk than it protects them from, we
may delay publication until users have had the chance to apply the patch, never
beyond that, and the reason is stated when we do publish.

## Security updates

Security updates are **free of charge**, and will stay that way: that is a
published commitment, adopted on **2026-08-25**, not a price we reserve the
right to revisit for a fix. Every security update made available during the
support period **remains available for at least 10 years** after it was issued,
or for the remainder of the support period, whichever is longer.

Said plainly, because a policy that overstates itself is worth nothing: today
there is no public distribution channel for the product binaries and no
advisory channel. Releases go to a private registry, and no security advisory
has ever been issued. Until that changes we do not claim that security updates
reach users without delay, nor that each one arrives with an advisory message
telling users what changed and what action, if any, they need to take (Annex I,
Part II, point (8)). When a public distribution channel and an advisory channel
are in place, they will be announced at <https://seetrex.com/security> and the
claim will be made there, with the date it became true.

Where technically feasible, new security updates are provided separately from
functionality updates — Annex I, Part II, point (2) — so that taking a fix
never requires taking a feature.

## Support period

Seetrex Compliance was placed on the market on **2026-08-24**. Its support
period ends on **2031-08-24 (August 2031)**. Until that date, vulnerabilities in
the product are handled under this policy and security updates are provided.

Every security update made available during the support period **remains
available for at least 10 years** after it was issued, or for the remainder of
the support period, whichever is longer (Article 13(9)).

## Verifying what you received

Release artifacts and signed tags carry a single OpenPGP signature. The public
key ships in this repository at `keys/release-signing-pubkey.asc`, and it is
also served from the web at
<https://seetrex.com/.well-known/release-signing-pubkey.asc>. That URL works
today: measured on **2026-08-25** it answered HTTP 200 with `content-type:
application/pgp-keys` and 441 bytes, byte-identical to the copy in this
repository. The key is the one artefact of this policy the apex already serves;
the other two paths named above are not. Compare fingerprints across independent
channels, and never trust a key only through the channel that served you the
artifact it signs.
