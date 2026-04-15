# frozen_string_literal: true

module CvssTo31
  # Raised when a CVSS vector string is malformed or fails cvss-suite validation.
  class Error < StandardError; end

  # Raised when the CVSS version of the input cannot be converted to 3.1
  # (e.g. an unrecognised future version).
  class UnsupportedVersionError < Error; end
end
