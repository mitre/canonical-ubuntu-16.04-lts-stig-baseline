control "V-75499" do
  title "There must be no .shosts files on the Ubuntu operating system."
  desc  "The .shosts files are used to configure host-based authentication for
individual users or the system via SSH. Host-based authentication is not
sufficient for preventing unauthorized access to the system, as it does not
require interactive identification and authentication of a connection request,
or for the use of two-factor authentication."
  impact 0.7
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-75499"
  tag "rid": "SV-90179r1_rule"
  tag "stig_id": "UBTU-16-010350"
  tag "fix_id": "F-82127r1_fix"
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
  desc "check", "Verify there are no \".shosts\" files on the Ubuntu operating
system.

Check the system for the existence of these files with the following command:

# sudo find / -name '*.shosts'

If any \".shosts\" files are found, this is a finding."
  tag "fix": "Remove any found \".shosts\" files from the Ubuntu operating
system.

# rm /[path]/[to]/[file]/.shosts"

  describe command("sudo find / -name '*.shosts'") do
    its('exit_status') { should eq 0 }
    its('stdout.strip') { should be_empty }
  end
end

