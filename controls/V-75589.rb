control "V-75589" do
  title "The Ubuntu operating system must use a separate file system for /var."
  desc  "The use of separate file systems for different paths can protect the
system from failures resulting from a file system becoming full or failing."
  impact 0.3
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-75589"
  tag "rid": "SV-90269r1_rule"
  tag "stig_id": "UBTU-16-010920"
  tag "fix_id": "F-82217r1_fix"
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
  desc "check", "Verify that a separate file system/partition has been created
for \"/var\".

Check that a file system/partition has been created for \"/var\" with the
following command:

# grep /var /etc/fstab
UUID=c274f65f /var ext4 noatime,nobarrier 1 2

If a separate entry for \"/var\" is not in use, this is a finding."
  desc "fix", "Migrate the \"/var\" path onto a separate file system."

  describe mount('/var') do
    it { should be_mounted }
  end
end

