# frozen_string_literal: true

control 'V-75443' do
  title "The Ubuntu operating system must limit the number of concurrent
sessions to ten for all accounts and/or account types."
  desc  "Ubuntu operating system management includes the ability to control the
number of users and user sessions that utilize an Ubuntu operating system.
Limiting the number of allowed users and sessions per user is helpful in
reducing the risks related to DoS attacks.

    This requirement addresses concurrent sessions for information system
accounts and does not address concurrent sessions by single users via multiple
system accounts. The maximum number of concurrent sessions should be defined
based upon mission needs and the operational environment for each system.
  "
  impact 0.3
  tag "gtitle": 'SRG-OS-000027-GPOS-00008'
  tag "gid": 'V-75443'
  tag "rid": 'SV-90123r2_rule'
  tag "stig_id": 'UBTU-16-010070'
  tag "fix_id": 'F-82071r1_fix'
  tag "cci": ['CCI-000054']
  tag "nist": %w[AC-10 Rev_4]
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
  desc 'check', "Verify that the Ubuntu operating system limits the number of
concurrent sessions to \"10\" for all accounts and/or account types by running
the following command:

# grep maxlogins /etc/security/limits.conf

The result must contain the following line:

* hard maxlogins 10

If the \"maxlogins\" item is missing or the value is not set to \"10\" or less,
or is commented out,  this is a finding."
  desc 'fix', "Configure the Ubuntu operating system to limit the number of
concurrent sessions to ten for all accounts and/or account types.

Add the following line to the top of the /etc/security/limits.conf:

* hard maxlogins 10"

  describe limits_conf do
    its('*') { should include ['hard', 'maxlogins', input('maxlogins').to_s] }
  end
end
