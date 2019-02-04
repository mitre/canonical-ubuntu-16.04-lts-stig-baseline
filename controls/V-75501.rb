control "V-75501" do
  title "There must be no shosts.equiv files on the Ubuntu operating system."
  desc  "The shosts.equiv files are used to configure host-based authentication
for the system via SSH. Host-based authentication is not sufficient for
preventing unauthorized access to the system, as it does not require
interactive identification and authentication of a connection request, or for
the use of two-factor authentication."
  impact 0.7
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-75501"
  tag "rid": "SV-90181r2_rule"
  tag "stig_id": "UBTU-16-010360"
  tag "fix_id": "F-82129r1_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
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
  desc "check", "Verify there are no \"shosts.equiv\" files on the Ubuntu
operating system.

Check for the existence of these files with the following command:

# find / -name shosts.equiv

If a \"shosts.equiv\" file is found, this is a finding."
  desc "fix", "Remove any found \"shosts.equiv\" files from the Ubuntu operating
system.

# rm /etc/ssh/shosts.equiv"

  describe command("sudo find / -name shosts.equiv") do
    its('exit_status') { should eq 0 }
    its('stdout.strip') { should be_empty }
  end
end

