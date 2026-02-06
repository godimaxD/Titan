---
name: Bug report
description: Report a reproducible problem
labels: bug
body:
  - type: textarea
    attributes:
      label: Summary
      description: A clear and concise description of the bug.
    validations:
      required: true
  - type: textarea
    attributes:
      label: Steps to reproduce
      description: Provide exact steps so we can reproduce the issue.
      placeholder: |
        1. Go to '...'
        2. Click '...'
        3. See error
    validations:
      required: true
  - type: textarea
    attributes:
      label: Expected behavior
    validations:
      required: true
  - type: textarea
    attributes:
      label: Actual behavior
    validations:
      required: true
  - type: textarea
    attributes:
      label: Environment
      description: Go version, OS, and any relevant configuration (redact secrets).
      placeholder: |
        Go: 1.x
        OS: macOS/Linux/Windows
    validations:
      required: true
