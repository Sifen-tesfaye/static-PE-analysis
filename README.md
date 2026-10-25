#  PE Analysis and Educational Hashing Demonstration

## Included work
- PE inspection utility and import-analysis source code.
- Compiled PE import-report utility.
- Static analysis evidence and parser regression reports.
- Compile-time hashing demonstration source, if included.
- Sample metadata, import cross-validation, and signature assessment.

## Scope and limitations
- The sample was analyzed statically; it was not executed.
- The hashing demonstration illustrates a hashing concept and does not
  implement complete Windows API resolution or import hiding.
- The included work is not a completed Windows malware loader.
- Process spoofing, encrypted payload execution, and remote injection
  are not implemented by these included components.
- No trusted-publisher signature is claimed. The signature assessment
  should be read from the included evidence.
- Regression tests are targeted tests, not proof of exhaustive security.

## Safety
The sample is intended for static educational analysis. An unsigned
file is not, by itself, proof that the file is malicious.
