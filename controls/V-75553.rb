control "V-75553" do
  title "Pluggable Authentication Module (PAM) must prohibit the use of cached
authentications after one day."
  desc  "If cached authentication information is out-of-date, the validity of
the authentication information may be questionable."
  impact 0.5
  tag "gtitle": "SRG-OS-000383-GPOS-00166"
  tag "gid": "V-75553"
  tag "rid": "SV-90233r2_rule"
  tag "stig_id": "UBTU-16-010690"
  tag "fix_id": "F-82181r2_fix"
  tag "cci": ["CCI-002007"]
  tag "nist": ["IA-5 (13)", "Rev_4"]
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
  desc "check", "Verify that Pluggable Authentication Module (PAM) prohibits the
use of cached authentications after one day.

Note: If smart card authentication is not being used on the system this item is
Not Applicable.

Check that PAM prohibits the use of cached authentications after one day with
the following command:

# sudo grep -i \"timestamp_timeout\" /etc/pam.d/*

timestamp_timeout=86400

If \"timestamp_timeout\" is not set to a value of \"86400\" or less, or is
commented out, this is a finding."
  desc "fix", "Configure Pluggable Authentication Module (PAM) to prohibit the
use of cached authentications after one day.

Add or change the following line in \"/etc/pam.d/common-auth\" or
\"/etc/pam.d/common-session\" just below the line \"[pam]\".

timestamp_timeout = 86400"
end

