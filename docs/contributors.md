# Contributors

This document credits those who conceptualized and/or implemented features for
FakeNet-NG.

## Legacy

FakeNet-NG is based on the original
[FakeNet](https://practicalmalwareanalysis.com/fakenet/) tool developed by
Andrew Honig and Michael Sikorski, which is still the tool of choice for
malware analysis on Windows XP.

## Windows

Peter Kacherginsky [implemented
FakeNet-NG](https://www.mandiant.com/resources/blog/fakenet-ng-next-gen)
targeting modern versions of Windows.

## Linux and Core

Michael Bailey [implemented FakeNet-NG on
Linux](https://www.mandiant.com/resources/blog/introducing-linux-support-fakenet-ng-flares-next-generation-dynamic-network-analysis-tool),
and later refactored FakeNet-NG to use this as the unified packet processing
logic for both Windows and Linux.

## Content-Based Protocol Detection

The original FakeNet-NG was able to automatically handle SSL; meanwhile, Joshua
Homan developed the original concept of using a protocol "taste" callback to
sample traffic and direct clients to the appropriate server ports. Matthew
Haigh, Michael Bailey, and Peter Kacherginsky conceptualized the Proxy Listener
and Hidden Listener mechanisms for introducing both of these content-based
protocol detection features to FakeNet-NG. Matthew Haigh then [implemented
Content-Based Protocol
Detection](https://www.mandiant.com/content/fireeye-www/en_US/blog/threat-research/2017/10/fakenet-content-based-protocol-detection.html).

## HTML- and Text-Based NBI After-Reporting

Google Summer of Code contributor Beleswar Prasad (@3V3RYONE) worked with
mentor Tina Johnson (@tinajohnson) to add HTML- and text-based reporting of
network-based indicators (NBIs) to FakeNet-NG, requiring significant work
throughout the codebase to facilitate the necessary communication and tracking
between components.
