# frozen_string_literal: true

require 'spec_helper'

RSpec.describe CvssTo31 do
  describe '.convert' do
    subject(:convert) { described_class.convert(input) }

    # -------------------------------------------------------------------------
    # CVSS 3.1 passthrough
    # -------------------------------------------------------------------------

    context 'with a CVSS 3.1 vector string' do
      let(:input) { 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H' }

      it 'returns a valid CvssSuite object' do
        expect(convert.valid?).to be true
      end

      it 'returns a CVSS 3.1 vector unchanged' do
        expect(convert.vector).to eq(input)
      end

      it 'returns the correct base score' do
        expect(convert.base_score).to eq(10.0)
      end
    end

    context 'with a CVSS 3.1 CvssSuite object as input' do
      let(:input) { CvssSuite.new('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H') }

      it 'returns the same object (passthrough)' do
        expect(convert).to equal(input)
      end
    end

    # -------------------------------------------------------------------------
    # CVSS 3.0 → 3.1 (lossless re-stamp)
    # -------------------------------------------------------------------------

    context 'with a CVSS 3.0 vector string' do
      let(:input) { 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H' }

      it 'returns a valid CVSS 3.1 object' do
        expect(convert.valid?).to be true
        expect(convert.version.to_s).to eq('3.1')
      end

      it 'produces the corresponding CVSS 3.1 vector string' do
        expect(convert.vector).to eq('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H')
      end

      it 'preserves the base score' do
        expect(convert.base_score).to eq(10.0)
      end
    end

    context 'with a CVSS 3.0 CvssSuite object as input' do
      let(:input) { CvssSuite.new('CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H') }

      it 'outputs a CVSS 3.1 object' do
        expect(convert.version.to_s).to eq('3.1')
      end

      it 'produces the correct vector string' do
        expect(convert.vector).to eq('CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H')
      end
    end

    # -------------------------------------------------------------------------
    # CVSS 4.0 → 3.1 (down-conversion)
    # -------------------------------------------------------------------------

    context 'with a CVSS 4.0 vector — all High impacts, High subsequent impacts' do
      let(:input) { 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H' }

      it 'returns a valid CVSS 3.1 object' do
        expect(convert.valid?).to be true
        expect(convert.version.to_s).to eq('3.1')
      end

      it 'maps VC/VI/VA to C/I/A' do
        result = convert
        expect(result.vector).to include('/C:H/I:H/A:H')
      end

      it 'infers Scope:Changed from non-None subsequent impacts' do
        expect(convert.vector).to include('/S:C/')
      end

      it 'maps UI:None to UI:N' do
        expect(convert.vector).to include('/UI:N/')
      end
    end

    context 'with a CVSS 4.0 vector — Active user interaction, no subsequent impacts' do
      # UI:A (Active) → UI:R; SC/SI/SA all None → S:U
      let(:input) { 'CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N' }

      it 'maps UI:Active to UI:Required' do
        expect(convert.vector).to include('/UI:R/')
      end

      it 'infers Scope:Unchanged when all subsequent impacts are None' do
        expect(convert.vector).to include('/S:U/')
      end

      it 'maps AV/AC/PR directly' do
        expect(convert.vector).to start_with('CVSS:3.1/AV:L/AC:H/PR:L/')
      end

      it 'maps VC:L to C:L' do
        expect(convert.vector).to include('/C:L/')
      end
    end

    context 'with a CVSS 4.0 vector — Passive user interaction' do
      # UI:P (Passive) → UI:R
      let(:input) { 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:L/SI:N/SA:N' }

      it 'maps UI:Passive to UI:Required' do
        expect(convert.vector).to include('/UI:R/')
      end

      it 'infers Scope:Changed from SC:L' do
        expect(convert.vector).to include('/S:C/')
      end
    end

    context 'with a CVSS 4.0 CvssSuite object as input' do
      let(:input) { CvssSuite.new('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N') }

      it 'produces a valid CVSS 3.1 object' do
        expect(convert.valid?).to be true
        expect(convert.version.to_s).to eq('3.1')
      end
    end

    # -------------------------------------------------------------------------
    # CVSS 2.0 → 3.1 (approximate conversion)
    # -------------------------------------------------------------------------

    context 'with a CVSS 2.0 vector — Network, Low complexity, No auth, all Complete' do
      # AV:N AC:L Au:N → AV:N AC:L PR:N; C/I/A all Complete → H/H/H
      let(:input) { 'AV:N/AC:L/Au:N/C:C/I:C/A:C' }

      it 'returns a valid CVSS 3.1 object' do
        expect(convert.valid?).to be true
        expect(convert.version.to_s).to eq('3.1')
      end

      it 'produces the expected vector' do
        expect(convert.vector).to eq('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
      end

      it 'sets UI to None (no v2 equivalent)' do
        expect(convert.vector).to include('/UI:N/')
      end

      it 'sets Scope to Unchanged (no v2 equivalent)' do
        expect(convert.vector).to include('/S:U/')
      end

      it 'returns a high base score' do
        expect(convert.base_score).to be >= 9.0
      end
    end

    context 'with a CVSS 2.0 vector — Local, High complexity, Single auth, Partial impacts' do
      # AV:L AC:H Au:S → AV:L AC:H PR:H; C/I Partial → L/L, A:None
      let(:input) { 'AV:L/AC:H/Au:S/C:P/I:P/A:N' }

      it 'maps AC:H to AC:H' do
        expect(convert.vector).to include('/AC:H/')
      end

      it 'maps Au:S to PR:H' do
        expect(convert.vector).to include('/PR:H/')
      end

      it 'maps Partial impact to Low' do
        expect(convert.vector).to include('/C:L/I:L/A:N')
      end
    end

    context 'with a CVSS 2.0 vector — Medium complexity (maps to AC:H)' do
      let(:input) { 'AV:N/AC:M/Au:N/C:P/I:P/A:P' }

      it 'maps AC:M to AC:H' do
        expect(convert.vector).to include('/AC:H/')
      end
    end

    context 'with a CVSS 2.0 vector — Adjacent, Multiple auth' do
      # Au:M → PR:H
      let(:input) { 'AV:A/AC:H/Au:M/C:N/I:C/A:C' }

      it 'maps Au:M to PR:H' do
        expect(convert.vector).to include('/PR:H/')
      end

      it 'maps AV:A correctly' do
        expect(convert.vector).to start_with('CVSS:3.1/AV:A/')
      end
    end

    context 'with a CVSS 2.0 CvssSuite object as input' do
      let(:input) { CvssSuite.new('AV:N/AC:L/Au:N/C:C/I:C/A:C') }

      it 'accepts a CvssSuite object and converts it' do
        expect(convert.valid?).to be true
        expect(convert.version.to_s).to eq('3.1')
      end
    end

    # -------------------------------------------------------------------------
    # Error cases
    # -------------------------------------------------------------------------

    context 'with an invalid vector string' do
      let(:input) { 'NOTCVSS' }

      it 'raises CvssTo31::Error' do
        expect { convert }.to raise_error(CvssTo31::Error)
      end
    end

    context 'with an unsupported CVSS version' do
      it 'raises CvssTo31::UnsupportedVersionError' do
        # Use a plain double to simulate a hypothetical future CVSS version
        # without being constrained to a specific CvssSuite class interface.
        fake = double('CvssSuite::Cvss', valid?: true, version: '5.0')
        expect { described_class.convert(fake) }.to raise_error(CvssTo31::UnsupportedVersionError)
      end
    end
  end
end
