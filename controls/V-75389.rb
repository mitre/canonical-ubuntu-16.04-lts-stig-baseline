platform_name = input('platform_name')
platform_release = input('platform_release')
supported_until = input('supported_until')

control "V-75389" do
  title "The Ubuntu operating system must be a vendor supported release."
  desc  "An Ubuntu operating system release is considered \"supported\" if the
vendor continues to provide security patches for the product. With an
unsupported release, it will not be possible to resolve security issues
discovered in the system software."
  impact 0.7
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-75389"
  tag "rid": "SV-90069r1_rule"
  tag "stig_id": "UBTU-16-010000"
  tag "fix_id": "F-82017r1_fix"
  tag "cci": ["CCI-001230"]
  tag "nist": ["SI-2 d", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  desc "check", "Verify the version of the Ubuntu operating system is vendor
supported.

Check the version of the Ubuntu operating system with the following command:

# cat /etc/lsb-release

DISTRIB_RELEASE=16.04
DISTRIB_CODENAME=xenial
DISTRIB_DESCRIPTION=\"Ubuntu 16.04.1 LTS\"

Current End of Life for Ubuntu 16.04 LTS is April 2021.

If the release is not supported by the vendor, this is a finding."
  desc "fix", "Upgrade to a supported version of the Ubuntu operating system."

  describe platform.name do
    it { should cmp platform_name }
  end

  describe platform.release do
    it { should cmp platform_release }
  end

  describe "The current system is still within its End of Life of #{supported_until}" do
    subject { Date.today <= Date.parse(supported_until) }
    it { should be true }
  end
end

