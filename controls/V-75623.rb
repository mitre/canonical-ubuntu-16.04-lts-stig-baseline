control "V-75623" do
  title "The Ubuntu operating system must notify the System Administrator (SA)
and Information System Security Officer (ISSO) (at a minimum) via email when
allocated audit record storage volume reaches 75% of the repository maximum
audit record storage capacity."
  desc  "If security personnel are not notified immediately when storage volume
reaches 75% utilization, they are unable to plan for audit record storage
capacity expansion."
  impact 0.5
  tag "gtitle": "SRG-OS-000343-GPOS-00134"
  tag "gid": "V-75623"
  tag "rid": "SV-90303r2_rule"
  tag "stig_id": "UBTU-16-020030"
  tag "fix_id": "F-82251r2_fix"
  tag "cci": ["CCI-001855"]
  tag "nist": ["AU-5 (1)", "Rev_4"]
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
  desc "check", "Verify the Ubuntu operating system notifies the System
Administrator (SA) and Information System Security Officer (ISSO) (at a
minimum) via email when allocated audit record storage volume reaches 75% of
the repository maximum audit record storage capacity.

Check that the Ubuntu operating system notifies the SA and ISSO (at a minimum)
via email when allocated audit record storage volume reaches 75% of the
repository maximum audit record storage capacity with the following commands:

#sudo grep space_left_action /etc/audit/auditd.conf

space_left_action email

If the space_left_action is set to \"email\" check the value of the
\"action_mail_acct\" parameter with the following command:

#sudo grep action_mail_acct parameter /etc/audit/auditd.conf

action_mail_acct parameter root@localhost

If the space_left_action or the action_mail_accnt parameters are set to blanks,
this is a finding.

If the space_left_action is set to \"syslog\", the system logs the event, this
is not a finding.

If the space_left_action is set to \"exec\", the system executes a designated
script. If this script informs the SA of the event, this is not a finding.

The action_mail_acct parameter, if missing, defaults to \"root\". If the
\"action_mail_acct parameter\" is not set to the e-mail address of the system
administrator(s) and/or ISSO, this is a finding.

Note: If the email address of the system administrator is on a remote system a
mail package must be available."
  tag "fix": "Configure the operating system to immediately notify the SA and
ISSO (at a minimum) via email when allocated audit record storage volume
reaches 75% of the repository maximum audit record storage capacity.

Edit \"/etc/audit/auditd.conf\" and set the \"space_left_action\" parameter to
\"exec\", \"email\", or \"syslog\". If the \"space_left_action\" parameter is
set to \"email\" set the \"action_mail_acct\" parameter to an e-mail address
for the System Administrator (SA) and Information System Security Officer
(ISSO)."
end

