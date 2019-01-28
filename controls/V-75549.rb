control "V-75549" do
  title "The root account must be the only account having unrestricted access
to the system."
  desc  "If an account other than root also has a User Identifier (UID) of
\"0\", it has root authority, giving that account unrestricted access to the
entire Ubuntu operating system. Multiple accounts with a UID of \"0\" afford an
opportunity for potential intruders to guess a password for a privileged
account."
  impact 0.7
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-75549"
  tag "rid": "SV-90229r1_rule"
  tag "stig_id": "UBTU-16-010670"
  tag "fix_id": "F-82177r1_fix"
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
  desc "check", "Check the Ubuntu operating system for duplicate User ID (UID)
\"0\" assignments with the following command:

# awk -F: '$3 == 0 {print $1}' /etc/passwd

root

If any accounts other than root have a UID of \"0\", this is a finding."
  tag "fix": "Change the User ID (UID) of any account on the system, other than
root, that has a UID of \"0\".

If the account is associated with system commands or applications, the UID
should be changed to one greater than \"0\" but less than \"1000\". Otherwise,
assign a UID of greater than \"1000\" that has not already been assigned."
end

