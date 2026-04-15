# cvss-to-3.1

A small Ruby gem that normalizes CVSS vectors from mixed versions into a CVSS 3.1 object.

It accepts CVSS 2.0, 3.0, 3.1, and 4.0 input and returns a scored `CvssSuite::Cvss31` object so downstream systems can compare and store values in one format.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'cvss-to-3.1'
```

Then run:

```bash
bundle install
```

Or install directly:

```bash
gem install cvss-to-3.1
```

## Usage

```ruby
require 'cvss_to_31'

result = CvssTo31.convert('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H')

result.version.to_s # => "3.1"
result.vector       # => "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
result.base_score   # => 10.0
```

The API accepts either a vector string or a `CvssSuite` object:

```ruby
v2 = CvssSuite.new('AV:N/AC:L/Au:N/C:C/I:C/A:C')
CvssTo31.convert(v2)
```

## Supported Conversion Logic

### CVSS 3.1 -> 3.1

Passthrough. A valid 3.1 vector/object is returned unchanged.

### CVSS 3.0 -> 3.1

Lossless version re-stamp (`CVSS:3.0` -> `CVSS:3.1`) with metrics preserved.

### CVSS 2.0 -> 3.1

CVSS 2.0 lacks some fields required by 3.1, so this conversion is approximate.

| CVSS 2.0 metric | CVSS 2.0 value | CVSS 3.1 metric | CVSS 3.1 value | Rationale |
|---|---|---|---|---|
| AV | N / A / L | AV | N / A / L | Direct equivalents |
| AC | L | AC | L | Low complexity stays Low |
| AC | M / H | AC | H | Medium/High collapse to High |
| Au | N | PR | N | No authentication required |
| Au | S / M | PR | H | Any authentication requirement maps to High privileges |
| C / I / A | N | C / I / A | N | No impact |
| C / I / A | P | C / I / A | L | Partial impact maps to Low |
| C / I / A | C | C / I / A | H | Complete impact maps to High |
| (none) | - | UI | N | No CVSS 2.0 equivalent |
| (none) | - | S | U | No CVSS 2.0 equivalent |

### CVSS 4.0 -> 3.1

CVSS 4.0 includes metrics not present in 3.1 and vice versa. The gem applies the following normalization:

| CVSS 4.0 metric | CVSS 4.0 value | CVSS 3.1 metric | CVSS 3.1 value | Rationale |
|---|---|---|---|---|
| AV | N / A / L / P | AV | N / A / L / P | Direct mapping |
| AC | L / H | AC | L / H | Direct mapping |
| PR | N / L / H | PR | N / L / H | Direct mapping |
| UI | N | UI | N | Direct mapping |
| UI | A / P | UI | R | Active/Passive collapse to Required |
| VC / VI / VA | N / L / H | C / I / A | N / L / H | Victim impacts map to CIA |
| SC / SI / SA | any L or H present | S | C | Any subsequent impact implies Scope Changed |
| SC / SI / SA | all N | S | U | No subsequent impact implies Scope Unchanged |

## Errors

`CvssTo31.convert` raises:

- `CvssTo31::Error` for invalid vectors
- `CvssTo31::UnsupportedVersionError` for unsupported CVSS versions

## Development

Run tests:

```bash
bundle exec rspec
```

Build the gem:

```bash
gem build cvss-to-3.1.gemspec
```

## License

Licensed under the BSD 2-Clause License. See LICENSE.
