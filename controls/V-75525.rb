# frozen_string_literal: true

control 'V-75525' do
  title "The Ubuntu operating system must use cryptographic mechanisms to
protect the integrity of audit tools."
  desc  "Protecting the integrity of the tools used for auditing purposes is a
critical step toward ensuring the integrity of audit information. Audit
information includes all information (e.g., audit records, audit settings, and
audit reports) needed to successfully audit information system activity.

    Audit tools include, but are not limited to, vendor-provided and open
source audit tools needed to successfully view and manipulate audit information
system activity and records. Audit tools include custom queries and report
generators.

    It is not uncommon for attackers to replace the audit tools or inject code
into the existing tools with the purpose of providing the capability to hide or
erase system activity from the audit logs.

    To address this risk, audit tools must be cryptographically signed in order
to provide the capability to identify when the audit tools have been modified,
manipulated, or replaced. An example is a checksum hash of the file or files.
  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000278-GPOS-00108'
  tag "gid": 'V-75525'
  tag "rid": 'SV-90205r2_rule'
  tag "stig_id": 'UBTU-16-010550'
  tag "fix_id": 'F-82153r1_fix'
  tag "cci": ['CCI-001496']
  tag "nist": ['AU-9 (3)', 'Rev_4']
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
  desc 'check', "Verify that Advanced Intrusion Detection Environment (AIDE) to
properly configured to use cryptographic mechanisms to protect the integrity of
audit tools.

Check the selection lines that aide is configured to add/check with the
following command:

# egrep '(\\/usr\\/sbin\\/(audit|au))' /etc/aide/aide.conf

/usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattr+sha512
/usr/sbin/auditd p+i+n+u+g+s+b+acl+xattr+sha512
/usr/sbin/ausearch p+i+n+u+g+s+b+acl+xattr+sha512
/usr/sbin/aureport p+i+n+u+g+s+b+acl+xattr+sha512
/usr/sbin/autrace p+i+n+u+g+s+b+acl+xattr+sha512
/usr/sbin/audispd p+i+n+u+g+s+b+acl+xattr+sha512
/usr/sbin/augenrules p+i+n+u+g+s+b+acl+xattr+sha512

If any of the seven audit tools does not have an appropriate selection line,
this is a finding."
  desc 'fix', "Add or update the following selection lines to
\"/etc/aide/aide.conf\", in order to protect the integrity of the audit tools.

# Audit Tools
/usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattr+sha512
/usr/sbin/auditd p+i+n+u+g+s+b+acl+xattr+sha512
/usr/sbin/ausearch p+i+n+u+g+s+b+acl+xattr+sha512
/usr/sbin/aureport p+i+n+u+g+s+b+acl+xattr+sha512
/usr/sbin/autrace p+i+n+u+g+s+b+acl+xattr+sha512
/usr/sbin/audispd p+i+n+u+g+s+b+acl+xattr+sha512
/usr/sbin/augenrules p+i+n+u+g+s+b+acl+xattr+sha512"

  aide_conf_exists = aide_conf.exist?

  if aide_conf_exists
    describe aide_conf.where { selection_line == '/usr/sbin/auditctl' } do
      its('rules') { should include ['p', 'i', 'n', 'u', 'g', 's', 'b', 'acl', 'xattr' 'sha512'] }
    end

    describe aide_conf.where { selection_line == '/usr/sbin/auditd' } do
      its('rules') { should include ['p', 'i', 'n', 'u', 'g', 's', 'b', 'acl', 'xattr' 'sha512'] }
    end

    describe aide_conf.where { selection_line == '/usr/sbin/ausearch' } do
      its('rules') { should include ['p', 'i', 'n', 'u', 'g', 's', 'b', 'acl', 'xattr' 'sha512'] }
    end

    describe aide_conf.where { selection_line == '/usr/sbin/aureport' } do
      its('rules') { should include ['p', 'i', 'n', 'u', 'g', 's', 'b', 'acl', 'xattr' 'sha512'] }
    end

    describe aide_conf.where { selection_line == '/usr/sbin/autrace' } do
      its('rules') { should include ['p', 'i', 'n', 'u', 'g', 's', 'b', 'acl', 'xattr' 'sha512'] }
    end

    describe aide_conf.where { selection_line == '/usr/sbin/audispd' } do
      its('rules') { should include ['p', 'i', 'n', 'u', 'g', 's', 'b', 'acl', 'xattr' 'sha512'] }
    end

    describe aide_conf.where { selection_line == '/usr/sbin/augenrules' } do
      its('rules') { should include ['p', 'i', 'n', 'u', 'g', 's', 'b', 'acl', 'xattr' 'sha512'] }
    end
  else
    describe 'aide.conf file exists' do
      subject { aide_conf_exists }
      it { should be true }
    end
  end
end
