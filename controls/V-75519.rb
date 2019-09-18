# frozen_string_literal: true

control 'V-75519' do
  title "The file integrity tool must be configured to verify Access Control
Lists (ACLs)."
  desc  "ACLs can provide permissions beyond those permitted through the file
mode and must be verified by file integrity tools."
  impact 0.3
  tag "gtitle": 'SRG-OS-000480-GPOS-00227'
  tag "gid": 'V-75519'
  tag "rid": 'SV-90199r3_rule'
  tag "stig_id": 'UBTU-16-010520'
  tag "fix_id": 'F-82147r1_fix'
  tag "cci": ['CCI-000366']
  tag "nist": ['CM-6 b', 'Rev_4']
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
  desc 'check', "Verify the file integrity tool is configured to verify Access
Control Lists (ACLs).

Use the following command to determine if the file is in a location other than
\"/etc/aide/aide.conf\":

# find / -name aide.conf

Check the \"aide.conf\" file to determine if the \"acl\" rule has been added to
the rule list being applied to the files and directories selection lists with
the following command:

# egrep \"[+]?acl\" /etc/aide/aide.conf

VarFile = OwnerMode+n+l+X+acl

If the \"acl\" rule is not being used on all selection lines in the
\"/etc/aide.conf\" file, is commented out, or ACLs are not being checked by
another file integrity tool, this is a finding."
  desc 'fix', "Configure the file integrity tool to check file and directory
ACLs.

If AIDE is installed, ensure the \"acl\" rule is present on all file and
directory selection lists."

  describe aide_conf.all_have_rule('acl') do
    it { should eq true }
  end
end
