# frozen_string_literal: true

require_relative 'lib/cvss_to_31/version'

Gem::Specification.new do |spec|
  spec.name    = 'cvss-to-3.1'
  spec.version = CvssTo31::VERSION
  spec.authors = ['todb']
  spec.email   = ['todb@runzero.com']
  spec.summary = 'Convert any CVSS vector (v2, v3.0, v4.0) to a normalised CVSS 3.1 score'
  spec.description = <<~DESC
    A small, focused gem that normalises CVSS vectors from any version
    (2.0, 3.0, 3.1, or 4.0) to a CVSS 3.1 CvssSuite object.  Useful
    whenever a tool must compare or store scores across a live CVE feed
    that mixes CVSS versions.
  DESC

  spec.homepage = 'https://github.com/runZeroInc/cvss-to-3.1'
  spec.license  = 'BSD-2-Clause'

  spec.metadata = {
    'source_code_uri' => 'https://github.com/runZeroInc/cvss-to-3.1'
  }

  spec.files         = Dir['lib/**/*'] + %w[README.md LICENSE CHANGELOG.md]
  spec.require_paths = ['lib']

  spec.required_ruby_version = '>= 3.1'

  spec.add_dependency 'cvss-suite', '~> 4.1'

  spec.add_development_dependency 'rspec', '~> 3.13'
end
