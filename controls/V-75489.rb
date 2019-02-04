control "V-75489" do
  title "The Ubuntu operating system must require users to re-authenticate for
privilege escalation and changing roles."
  desc  "Without re-authentication, users may access resources or perform tasks
for which they do not have authorization.

    When Ubuntu operating systems provide the capability to escalate a
functional capability or change security roles, it is critical the user
re-authenticate.


  "
  impact 0.5
  tag "gtitle": "SRG-OS-000373-GPOS-00156"
  tag "satisfies": ["SRG-OS-000373-GPOS-00156", "SRG-OS-000373-GPOS-00157"]
  tag "gid": "V-75489"
  tag "rid": "SV-90169r2_rule"
  tag "stig_id": "UBTU-16-010300"
  tag "fix_id": "F-82117r2_fix"
  tag "cci": ["CCI-002038"]
  tag "nist": ["IA-11", "Rev_4"]
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
  desc "check", "Verify that \"/etc/sudoers\" has no occurrences of \"NOPASSWD\"
or \"!authenticate\".

Check that the \"/etc/sudoers\" file has no occurrences of \"NOPASSWD\" or
\"!authenticate\" by running the following command:

# sudo egrep -i '(nopasswd|!authenticate)' /etc/sudoers /etc/sudoers.d/*

%wheel ALL=(ALL) NOPASSWD: ALL

If any occurrences of \"NOPASSWD\" or \"!authenticate\" return from the
command, this is a finding."
  desc "fix", "Remove any occurrence of \"NOPASSWD\" or \"!authenticate\" found
in \"/etc/sudoers\" file or files in the \"/etc/sudoers.d\" directory."

  describe command("sudo egrep -r -i '(nopasswd|!authenticate)' /etc/sudoers.d/ /etc/sudoers") do
    its('stdout.strip') { should be_empty }
  end
end

