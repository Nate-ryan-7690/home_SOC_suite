# Contributing to Home SOC Suite — Night's Watch

Thank you for your interest in contributing to this project.

---

## Intended Use

This suite is designed for monitoring systems you own or have explicit 
authorization to monitor. Any contributions must align with this purpose.

---

## How to Contribute

### Reporting Bugs
- Open a GitHub Issue describing the problem
- Include your PowerShell version (`$PSVersionTable.PSVersion`)
- Include your Windows OS language
- Paste any error messages you received
- Describe what you expected vs what happened

### Suggesting Features
- Open a GitHub Issue with the label `enhancement`
- Describe the use case and why it would benefit the suite
- If you have a working implementation, mention it in the issue before opening a pull request

### Adding Language Support
The most welcome contribution is adding CPU counter paths for unsupported OS languages. To do this:
1. Find the localized counter path on your system by running:
```powershell
   Get-Counter -ListSet * | Where-Object { $_.CounterSetName -match "Process" }
```
2. Open a GitHub Issue with your language and the counter path
3. Or submit a pull request adding the path to the `$PathsToTry` array in `Get-WorkingCounterPath` in `Steward.ps1`

---

## Pull Request Guidelines

- Keep changes focused — one fix or feature per pull request
- Test on both PowerShell 5.1 and PowerShell 7+ before submitting
- Follow the existing code style and comment conventions
- Update the README if your change affects installation, configuration, or supported languages

---

## Development Notes

- All scripts must remain compatible with both PS 5.1 and PS 7+
- Use `$RootPath` for all file paths — never hardcode Desktop paths
- Follow PSScriptAnalyzer recommendations where possible
- Severity classification must remain consistent across all collectors

---

## Questions

Open a GitHub Issue and tag it `question`.
