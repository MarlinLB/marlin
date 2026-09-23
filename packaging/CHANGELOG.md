# Changelog

All notable changes to the `marlinlb` meta package will be documented in this file. Versioned in
`packaging/VERSION`. See the root `CHANGELOG.md` for how this fits the other components. This
file records changes to the meta package itself -- which pair of `marlinlb-xdp`/`marlinlb-daemon`
versions it pins -- not changes to either component, which carry their own changelogs.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- First release: `marlinlb-xdp`, `marlinlb-daemon` and the `marlinlb` meta package, built with
  nfpm from `packaging/nfpm/*.yaml` (`packaging/mkdeb.sh`).
