control "V-75471" do
  title "Passwords for new users must have a 24 hours/1 day minimum password
lifetime restriction."
  desc  "Enforcing a minimum password lifetime helps to prevent repeated
password changes to defeat the password reuse or history enforcement
requirement. If users are allowed to immediately and continually change their
password, then the password could be repeatedly changed in a short period of
time to defeat the organization's policy regarding password reuse."
  impact 0.5
  tag "gtitle": "SRG-OS-000075-GPOS-00043"
  tag "gid": "V-75471"
  tag "rid": "SV-90151r2_rule"
  tag "stig_id": "UBTU-16-010210"
  tag "fix_id": "F-82099r2_fix"
  tag "cci": ["CCI-000198"]
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
  desc "check", "Verify that the Ubuntu operating system enforces a 24 hours/1
day minimum password lifetime for new user accounts by running the following
command:

# grep -i pass_min_days /etc/login.defs

PASS_MIN_DAYS    1

If the \"PASS_MIN_DAYS\" parameter value is less than or equal to \"1\", or
commented out, this is a finding."
  desc "fix", "Configure the Ubuntu operating system to enforce a 24 hours/1 day
minimum password lifetime.

Add, or modify the following line in the \"/etc/login.defs\" file:

PASS_MIN_DAYS    1"

  describe login_defs do
    its('PASS_MIN_DAYS') { should >= '1' }
  end
end

