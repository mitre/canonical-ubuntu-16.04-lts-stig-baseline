control "V-75479" do
  title "The Ubuntu operating system must not have accounts configured with
blank or null passwords."
  desc  "If an account has an empty password, anyone could log on and run
commands with the privileges of that account. Accounts with empty passwords
should never be used in operational environments."
  impact 0.7
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-75479"
  tag "rid": "SV-90159r1_rule"
  tag "stig_id": "UBTU-16-010250"
  tag "fix_id": "F-82107r1_fix"
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
  desc "check", "To verify that null passwords cannot be used, run the following
command:

# grep pam_unix.so /etc/pam.d/* | grep nullok
If this produces any output, it may be possible to log on with accounts with
empty passwords.

If null passwords can be used, this is a finding."
  tag "fix": "If an account is configured for password authentication but does
not have an assigned password, it may be possible to log on to the account
without authenticating.

Remove any instances of the \"nullok\" option in files under \"/etc/pam.d/\" to
prevent logons with empty passwords."

  describe command("grep pam_unix.so /etc/pam.d/* | grep nullok") do
    its('stdout.strip') { should be_empty }
  end
end

