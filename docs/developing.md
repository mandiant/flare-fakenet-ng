Developing for FakeNet-NG
-------------------------

FireEye only:
* Create branches directly under the `fireeye/` GitHub repository, not under a
  private fork.

All contributors:
* Pull request comment should bear bulleted list for inclusion in change log.
* After review, but before merging, at reviewer discretion, either developer or
  reviewer must update the FakeNet-NG version as described below.

FakeNet Versioning
------------------

As of this writing, the minor version should be incremented any time there is a
merge that includes changes to a code or data file. Exceptions are:
* Modifications to documentation
* Whitespace changes
* Adding, removing, or modifying comments

Expressly included are changes that only modify banners, FakeNet logging
output, etc.

Here is where to update the version:

| File                 | How to update                                        |
|----------------------|------------------------------------------------------|
| `CHANGELOG.txt`      | Increment version, paste pull request comments       |
| `fakenet/fakenet.py` | Update version in banner string                      |
| `setup.py`           | Update `version` parameter to `setup()`              |

Various listeners report `FakeNet/1.3` as their version. As of this writing,
this is disregarded; only the banner, changelog, and setuptools versions are
updated. A future change should be issued to induce listeners to pull their
version number from a central location or not to report a version number at
all.
