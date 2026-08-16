LOKI TRAFFIC LAB - WINDOWS PORTABLE
===================================

This directory contains Windows-specific packaging and release files.
Shared diagnostic logic remains in ../src and the traffic-lab root scripts.

Contents:
  releases/                    Built Windows directories and ZIP releases.
  vendor/                      Windows-only bundled build dependencies.
  build-portable.ps1           Self-contained Windows build script.
  portable-connections.txt     Safe connections.txt distribution template.
  portable-test-plan.example.json
  PORTABLE-README.txt          README embedded in each distribution.
  THIRD-PARTY-NOTICES.txt      Notices embedded in each distribution.

Build from the repository root:
  & '.\traffic-lab\Portable windows\build-portable.ps1' -RuntimeIdentifier win-x64 -Zip

The default output is written to releases/.
