control "V-75597" do
  title "The /var/log directory must have mode 0770 or less permissive."
  desc  "Only authorized personnel should be aware of errors and the details of
the errors. Error messages are an indicator of an organization's operational
state or can identify the Ubuntu operating system or platform. Additionally,
Personally Identifiable Information (PII) and operational information must not
be revealed through error messages to unauthorized personnel or their
designated representatives.

    The structure and content of error messages must be carefully considered by
the organization and development team. The extent to which the information
system is able to identify and handle error conditions is guided by
organizational policy and operational requirements.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000206-GPOS-00084"
  tag "gid": "V-75597"
  tag "rid": "SV-90277r3_rule"
  tag "stig_id": "UBTU-16-010960"
  tag "fix_id": "F-82225r2_fix"
  tag "cci": ["CCI-001314"]
  tag "nist": ["SI-11 b", "Rev_4"]
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
  desc "check", "Verify that the \"/var/log\" directory has a mode of \"0770\"
or less.

Check the mode of the \"/var/log\" directory with the following command:

# stat -c \"%a %n\" /var/log

770

If a value of \"0770\" or less permissive is not returned, this is a finding."
  desc "fix", "Change the permissions of the directory \"/var/log\" to \"0770\"
by running the following command:

# sudo chmod 0770 /var/log"
end

