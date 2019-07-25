control "V-75799" do
  title "The Network Information Service (NIS) package must not be installed."
  desc  "Removing the Network Information Service (NIS) package decreases the
risk of the accidental (or intentional) activation of NIS or NIS+ services."
  impact 0.7
  tag "gtitle": "SRG-OS-000095-GPOS-00049"
  tag "gid": "V-75799"
  tag "rid": "SV-90479r2_rule"
  tag "stig_id": "UBTU-16-030010"
  tag "fix_id": "F-82429r1_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]
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
  desc "check", "Verify that the Network Information Service (NIS) package is
not installed on the Ubuntu operating system.

Check to see if the NIS package is installed with the following command:

#  sudo apt list nis

If the NIS package is installed, this is a finding."
  desc "fix", "Configure the Ubuntu operating system to disable non-essential
capabilities by removing the Network Information Service (NIS) package from the
system with the following command:

# sudo apt-get remove nis"

  describe package('nis') do
    it { should_not be_installed }
  end
end

