control "V-75473" do
  title "Passwords for new users must have a 60-day maximum password lifetime
restriction."
  desc  "Any password, no matter how complex, can eventually be cracked.
Therefore, passwords need to be changed periodically. If the Ubuntu operating
system does not limit the lifetime of passwords and force users to change their
passwords, there is the risk that the Ubuntu operating system passwords could
be compromised."
  impact 0.5
  tag "gtitle": "SRG-OS-000076-GPOS-00044"
  tag "gid": "V-75473"
  tag "rid": "SV-90153r2_rule"
  tag "stig_id": "UBTU-16-010220"
  tag "fix_id": "F-82101r2_fix"
  tag "cci": ["CCI-000199"]
  tag "nist": ["IA-5 (1) (d)", "Rev_4"]
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
  tag "check": "Verify that the Ubuntu operating system enforces a 60-day
maximum password lifetime for new user accounts by running the following
command:

# grep -i pass_max_days /etc/login.defs
PASS_MAX_DAYS    60

If the \"PASS_MAX_DAYS\" parameter value is less than \"60\", or commented out,
this is a finding."
  tag "fix": "Configure the Ubuntu operating system to enforce a 60-day maximum
password lifetime.

Add, or modify the following line in the \"/etc/login.defs\" file:

PASS_MAX_DAYS    60"
end

