control "V-75647" do
  title "The Ubuntu operating system must allow only the Information System
Security Manager (ISSM) (or individuals or roles appointed by the ISSM) to
select which auditable events are to be audited."
  desc  "Without the capability to restrict which roles and individuals can
select which events are audited, unauthorized personnel may be able to prevent
the auditing of critical events. Misconfigured audits may degrade the system's
performance by overwhelming the audit log. Misconfigured audits may also make
it more difficult to establish, correlate, and investigate the events relating
to an incident or identify those responsible for one."
  impact 0.5
  tag "gtitle": "SRG-OS-000063-GPOS-00032"
  tag "gid": "V-75647"
  tag "rid": "SV-90327r1_rule"
  tag "stig_id": "UBTU-16-020150"
  tag "fix_id": "F-82275r1_fix"
  tag "cci": ["CCI-000171"]
  tag "nist": ["AU-12 b", "Rev_4"]
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
  desc "check", "Verify that the /etc/audit/audit.rule and
/etc/audit/auditd.conf file have a mode of 0640 or less permissive by using the
following command:

# sudo ls -la /etc/audit/audit.rules

-rw-r----- 1 root root 1280 Feb 16 17:09 audit.rules
-rw-r----- 1 root root 621 Sep 22 2014 auditd.conf

If the \"/etc/audit/audit.rule\" or \"/etc/audit/auditd.conf\" file have a mode
more permissive than \"0640\", this is a finding."
  desc "fix", "Configure the /etc/audit/audit.rule and /etc/audit/auditd.conf
file to have a mode of 0640 with the following command:

# sudo chmod 0640 /etc/audit/audit.rule
# sudo chmod 0640 /etc/audit/audit.conf"
end

