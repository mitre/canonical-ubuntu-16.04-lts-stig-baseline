control "V-75493" do
  title "The Ubuntu operating system must enforce a delay of at least 4 seconds
between logon prompts following a failed logon attempt."
  desc  "Limiting the number of logon attempts over a certain time interval
reduces the chances that an unauthorized user may gain access to an account."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00226"
  tag "gid": "V-75493"
  tag "rid": "SV-90173r1_rule"
  tag "stig_id": "UBTU-16-010320"
  tag "fix_id": "F-82121r1_fix"
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
  desc "check", "Verify the Ubuntu operating system enforces a delay of at least
4 seconds between logon prompts following a failed logon attempt.

Check that the Ubuntu operating system enforces a delay of at least 4 seconds
between logon prompts with the following command:

# grep pam_faildelay /etc/pam.d/common-auth*

auth required pam_faildelay.so delay=4000000

If the line is not present, or is commented out, this is a finding."
  tag "fix": "Configure the Ubuntu operating system to enforce a delay of at
least 4 seconds between logon prompts following a failed logon attempt.

Edit the file \"/etc/pam.d/common-auth\" and set the parameter
\"pam_faildelay\" to a value of 4000000 or greater:

auth required pam_faildelay.so delay=4000000"
end

