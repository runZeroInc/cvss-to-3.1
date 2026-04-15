# frozen_string_literal: true

require 'cvss_suite'
require_relative 'error'

module CvssTo31
  # Converts any supported CVSS vector to a CVSS 3.1 {CvssSuite} object.
  #
  # Supported source versions:
  # - 2.0  (approximate — see notes below)
  # - 3.0  (lossless re-stamp of the version component)
  # - 3.1  (passthrough)
  # - 4.0  (down-conversion — see notes below)
  #
  # == CVSS 2.0 → 3.1 mapping notes
  #
  # CVSS v2 lacks several metrics that v3.1 requires, so this conversion is
  # necessarily approximate.  The mapping applied is:
  #
  # | v2 metric | v2 value | v3.1 metric | v3.1 value | Rationale |
  # |-----------|----------|-------------|------------|-----------|
  # | AV        | N/A/L    | AV          | N/A/L      | Direct equivalents |
  # | AC        | L        | AC          | L          | Low complexity stays Low |
  # | AC        | M/H      | AC          | H          | Medium/High collapse to High (worst-case) |
  # | Au        | N        | PR          | N          | No authentication required |
  # | Au        | S/M      | PR          | H          | Any authentication ≈ high privilege required |
  # | C/I/A     | N        | C/I/A       | N          | No impact |
  # | C/I/A     | P        | C/I/A       | L          | Partial impact ≈ Low |
  # | C/I/A     | C        | C/I/A       | H          | Complete impact ≈ High |
  # | (none)    | —        | UI          | N          | No v2 equivalent; defaults to None |
  # | (none)    | —        | S           | U          | No v2 equivalent; defaults to Unchanged |
  #
  # == CVSS 4.0 → 3.1 mapping notes
  #
  # The down-conversion maps Base metrics directly where names match, collapses
  # the v4.0 User Interaction values (Active/Passive → Required, None → None),
  # and infers Scope from the three Subsequent Impact metrics (SC/SI/SA: any
  # High or Low value → Changed; all None → Unchanged).  Victim/Consumer Impact
  # metrics (VC/VI/VA) are used for the v3.1 C/I/A values.
  class Converter
    class << self
      # Convert a CVSS vector to CVSS 3.1.
      #
      # @param input [String, CvssSuite::Cvss] A CVSS vector string or an
      #   existing {CvssSuite} object.
      # @return [CvssSuite::Cvss31] A valid CVSS 3.1 object.
      # @raise [CvssTo31::Error] If the vector is invalid.
      # @raise [CvssTo31::UnsupportedVersionError] If the CVSS version is not
      #   one of 2.0, 3.0, 3.1, or 4.0.
      def convert(input)
        cvss = input.is_a?(String) ? CvssSuite.new(input) : input

        unless cvss.respond_to?(:valid?) && cvss.valid?
          raise Error, "Invalid CVSS vector: #{input.is_a?(String) ? input : input.vector}"
        end

        case cvss.version.to_s
        when "3.1" then cvss
        when "3.0" then from_3_0(cvss)
        when "4.0" then from_4_0(cvss)
        when "2"   then from_2_0(cvss)
        else
          raise UnsupportedVersionError, "Unsupported CVSS version: #{cvss.version}"
        end
      end

      private

      def from_3_0(cvss)
        CvssSuite.new(cvss.vector.sub("CVSS:3.0", "CVSS:3.1"))
      end

      def from_4_0(cvss)
        m     = parse_vector(cvss.vector)
        ui    = case m["UI"]; when "A", "P" then "R"; else "N"; end
        scope = [m["SC"], m["SI"], m["SA"]].any? { |v| v =~ /[HL]/ } ? "C" : "U"

        CvssSuite.new(
          "CVSS:3.1/AV:#{m["AV"]}/AC:#{m["AC"]}/PR:#{m["PR"]}" \
          "/UI:#{ui}/S:#{scope}/C:#{m["VC"]}/I:#{m["VI"]}/A:#{m["VA"]}"
        )
      end

      def from_2_0(cvss)
        m = parse_vector(cvss.vector)

        CvssSuite.new(
          "CVSS:3.1/AV:#{m["AV"]}/AC:#{map_v2_ac(m["AC"])}/PR:#{map_v2_au(m["Au"])}" \
          "/UI:N/S:U/C:#{map_v2_impact(m["C"])}/I:#{map_v2_impact(m["I"])}/A:#{map_v2_impact(m["A"])}"
        )
      end

      # Split a CVSS vector string into a metric hash.
      # Works for all versions; the leading "CVSS:X.Y" token is stored under
      # the key "CVSS" and is harmlessly ignored during metric lookups.
      def parse_vector(vector)
        vector.split('/').each_with_object({}) do |part, h|
          key, val = part.split(':', 2)
          h[key] = val
        end
      end

      # CVSS v2 AC: L → L; M or H → H (worst-case: higher complexity scores harder)
      def map_v2_ac(ac)
        case ac
        when "L"      then "L"
        when "M", "H" then "H"
        else raise Error, "Unknown CVSS v2 AC value: #{ac}"
        end
      end

      # CVSS v2 Au → v3.1 PR: N → N; S or M → H (any auth requirement = high privilege)
      def map_v2_au(au)
        case au
        when "S", "M" then "H"
        when "N"       then "N"
        else raise Error, "Unknown CVSS v2 Au value: #{au}"
        end
      end

      # CVSS v2 C/I/A impact: N → N, P → L, C → H
      def map_v2_impact(val)
        case val
        when "N" then "N"
        when "P" then "L"
        when "C" then "H"
        else raise Error, "Unknown CVSS v2 impact value: #{val}"
        end
      end
    end
  end
end
