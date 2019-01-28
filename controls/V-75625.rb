control "V-75625" do
  title "The System Administrator (SA) and Information System Security Officer
(ISSO) (at a minimum) must be alerted of an audit processing failure event."
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
  tag "gid": "V-75625"
  tag "rid": "SV-90305r2_rule"
  tag "stig_id": "UBTU-16-020040"
  tag "fix_id": "F-82253r1_fix"
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
  desc "check", "Verify that the System Administrator (SA) and Information
System Security Officer (ISSO) (at a minimum) are notified in the event of an
audit processing failure.

Check that the Ubuntu operating system notifies the SA and ISSO (at a minimum)
in the event of an audit processing failure with the following command:

#sudo grep space_left_action /etc/audit/auditd.conf

action_mail_acct = root

If the value of the \"action_mail_acct\" keyword is not set to \"root\" and/or
other accounts for security personnel, the \"action_mail_acct\" keyword is
missing, or the retuned line is commented out, this is a finding."
  tag "fix": "Configure \"auditd\" service to notify the System Administrator
(SA) and Information System Security Officer (ISSO) in the event of an audit
processing failure.

Edit the following line in \"/etc/audit/auditd.conf\" to ensure that
administrators are notified via email for those situations:

action_mail_acct = root"
end

