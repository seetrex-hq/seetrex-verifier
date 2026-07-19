# Contributing

Thank you for your interest in improving the Seetrex verification stack
(`seetrex-format`, `seetrex-verifier` and the package specification).

## How this repository works

This public repository is **not** the source of truth. Development happens in
a private repository; the public repository is **regenerated from a curated
export at every signed release tag**. That has two practical consequences for
contributors:

- **Your commits do not survive.** Accepted pull requests are reviewed here,
  then ported by hand into the private repository. When the next signed tag
  is exported, the public history is regenerated and your original commits
  are replaced by the exported snapshot.
- **Your attribution does.** Contributors of accepted changes are credited in
  the `NOTICE` file and in the `CHANGELOG` entry of the release that ships
  the change. If you want a specific attribution string, say so in the pull
  request.

Please open an issue before starting non-trivial work, so we can confirm the
change belongs in the open crates (the inference engine and the SaaS backend
are closed source and out of scope for this repository).

## Developer Certificate of Origin (DCO)

Every commit in a pull request must be signed off, certifying the
[Developer Certificate of Origin](https://developercertificate.org/):

```
Signed-off-by: Your Name <your.email@example.com>
```

Use `git commit -s` to add the sign-off automatically. Pull requests with
unsigned commits will not be merged. The sign-off certifies that you have
the right to submit the change under the Apache License, Version 2.0.

## License

By contributing, you agree that your contributions are licensed under the
Apache License, Version 2.0 (see `LICENSE`). Note that the license does not
grant trademark rights; see `NOTICE`.
