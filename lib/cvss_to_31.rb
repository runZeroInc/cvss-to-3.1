# frozen_string_literal: true

require_relative 'cvss_to_31/version'
require_relative 'cvss_to_31/error'
require_relative 'cvss_to_31/converter'

# Top-level namespace for the cvss-to-3.1 gem.
#
# Converts any supported CVSS vector (v2.0, v3.0, v3.1, or v4.0) to a
# normalised CVSS 3.1 {CvssSuite} object.
#
# @example Convert a CVSS 4.0 vector
#   result = CvssTo31.convert("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")
#   result.base_score   #=> 10.0
#   result.vector       #=> "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
#
# @example Convert a CVSS 2.0 vector
#   result = CvssTo31.convert("AV:N/AC:L/Au:N/C:C/I:C/A:C")
#   result.base_score   #=> 9.8
#   result.vector       #=> "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
module CvssTo31
  # Convert a CVSS vector string or {CvssSuite} object to CVSS 3.1.
  #
  # @param input [String, CvssSuite::Cvss] CVSS vector or existing object.
  # @return [CvssSuite::Cvss31] A valid, scored CVSS 3.1 object.
  # @raise [CvssTo31::Error] On invalid input.
  # @raise [CvssTo31::UnsupportedVersionError] On an unrecognised CVSS version.
  def self.convert(input)
    Converter.convert(input)
  end
end
