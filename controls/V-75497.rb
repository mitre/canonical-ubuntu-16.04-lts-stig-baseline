control "V-75497" do
  title "The Ubuntu operating system must display the date and time of the last
successful account logon upon logon."
  desc  "Providing users with feedback on when account accesses last occurred
facilitates user recognition and reporting of unauthorized account use."
  impact 0.3
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-75497"
  tag "rid": "SV-90177r1_rule"
  tag "stig_id": "UBTU-16-010340"
  tag "fix_id": "F-82125r1_fix"
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
  tag "check": "Verify users are provided with feedback on when account
accesses last occurred.

Check that \"pam_lastlog\" is used and not silent with the following command:

# grep pam_lastlog /etc/pam.d/login

session required pam_lastlog.so showfailed

If \"pam_lastlog\" is missing from \"/etc/pam.d/login\" file, or the \"silent\"
option is present, this is a finding."
  tag "fix": "Configure the Ubuntu operating system to provide users with
feedback on when account accesses last occurred by setting the required
configuration options in \"/etc/pam.d/postlogin-ac\".

Add the following line to the top of \"/etc/pam.d/login\":

session required pam_lastlog.so showfailed"
end

