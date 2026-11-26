# Contributing to DSB

Thanks for your interest! Bug reports, ideas and pull requests are all welcome.

## Reporting bugs

Open an issue with the **Bug report** template and include your version, OS/distribution and any error output.
For security problems, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

## Development

```bash
git clone https://github.com/Zyd93/deadlock-server-blocker-DSB.git
cd deadlock-server-blocker-DSB
python3 -m unittest discover -s tests -v
```

The tests use fakes and never touch your real firewall, so they are safe to run anywhere.

## Pull requests

- Keep changes focused; one fix or feature per pull request.
- Add or update tests for behaviour changes.
- Make sure the tests and `bash -n scripts/dsb-gui scripts/dsb-askpass install.sh uninstall.sh` pass.
- Follow the existing code style (standard library first, type hints, small functions).

By contributing you agree that your contribution is licensed under the [GPL-3.0](LICENSE).
