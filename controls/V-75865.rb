control "V-75865" do
  title "Cron logging must be implemented."
  desc  "Cron logging can be used to trace the successful or unsuccessful
execution of cron jobs. It can also be used to spot intrusions into the use of
the cron facility by unauthorized and malicious users."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-75865"
  tag "rid": "SV-90545r2_rule"
  tag "stig_id": "UBTU-16-030460"
  tag "fix_id": "F-82495r2_fix"
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
  desc "check", "Verify that \"rsyslog\" is configured to log cron events.

Check the configuration of \"/etc/rsyslog.d/50-default.conf\" for the cron
facility with the following commands:

Note: If another logging package is used, substitute the utility configuration
file for \"/etc/rsyslog.d/50-default.conf\".

# grep cron /etc/rsyslog.d/50-default.conf

cron.*                          /var/log/cron.log

If the commands do not return a response, check for cron logging all facilities
by inspecting the \"/etc/rsyslog.d/50-default.con\" file:

# more /etc/rsyslog.conf

Look for the following entry:

*.* /var/log/messages

If \"rsyslog\" is not logging messages for the cron facility or all facilities,
this is a finding."
  desc "fix", "Configure \"rsyslog\" to log all cron messages by adding or
updating the following line to \"/etc/rsyslog.d/50-default.conf\":

cron.* /var/log/cron.log

Note: The line must be added before the following entry if it exists in
\"/etc/rsyslog.d/50-default.conf\":

*.* ~ # discards everything"
end

