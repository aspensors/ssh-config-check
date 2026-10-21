# Contributing

Use Python 3.11+ and run `python -m unittest discover -s tests -v`.
Add a synthetic fixture for a behavioral change. Do not commit private host configs, keys or effective reports.

A rule needs an OpenSSH documentation reference, a precise observation and explicit limitations. Do not infer security from one option or silently treat unsupported syntax as complete. Include/Match evaluation belongs to OpenSSH; this prototype does not replace it. Prefer small changes with regression tests.
