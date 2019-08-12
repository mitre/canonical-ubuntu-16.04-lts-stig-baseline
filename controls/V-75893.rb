control "V-75893" do
  title "The Information System Security Officer (ISSO) and System
Administrator (SA) (at a minimum) must have mail aliases to be notified of an
audit processing failure."
  desc  "It is critical for the appropriate personnel to be aware if a system
is at risk of failing to process audit logs as required. Without this
notification, the security personnel may be unaware of an impending failure of
the audit capability, and system operation may be adversely affected.

    Audit processing failures include software/hardware errors, failures in the
audit capturing mechanisms, and audit storage capacity being reached or
exceeded.

    This requirement applies to each audit data storage repository (i.e.,
distinct information system component where audit records are stored), the
centralized audit storage capacity of organizations (i.e., all audit data
storage repositories combined), or both.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000046-GPOS-00022"
  tag "gid": "V-75893"
  tag "rid": "SV-90573r2_rule"
  tag "stig_id": "UBTU-16-030700"
  tag "fix_id": "F-82523r1_fix"
  tag "cci": ["CCI-000139"]
  tag "nist": ["AU-5 a", "Rev_4"]
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
  desc "check", "Verify that the administrators are notified in the event of an
audit processing failure.

Note: If postfix is not installed, this is Not Applicable.

Check that the \"/etc/aliases\" file has a defined value for \"root\".

# sudo grep \"postmaster: *root$\" /etc/aliases

If the command does not return a line, or the line is commented out, this is a
finding."
  desc "fix", "Configure the Ubuntu operating system to notify administrators in
the event of an audit processing failure.

Add/update the following line in \"/etc/aliases\":

postmaster: root"

  is_postfix_installed = package('postfix').installed?

  if is_postfix_installed
    describe command('grep "postmaster: *root$" /etc/aliases') do
      its('stdout') { should_not be_empty }
    end
  else
    impact 0
    describe "Control Not Applicable as postfix is not installed" do
      subject { is_postfix_installed }
      it { should be false }
    end
  end
end

